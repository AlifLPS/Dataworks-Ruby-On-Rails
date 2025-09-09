require "net/http"
require "openssl"
require "base64"
require "uri"
require "json"
require "rexml/document"

class DataworksConnector
  attr_accessor :project_name, :access_id, :access_secret, :endpoint
  attr_reader :last_error

  # Make keyword args optional so ConnectorsController#new can instantiate without params
  def initialize(project_name: "", access_id: "", access_secret: "", endpoint: "")
    @project_name = project_name.to_s.strip
    @access_id = access_id.to_s.strip
    @access_secret = access_secret.to_s.strip
    @endpoint = endpoint.to_s.strip
  end

  # Validates we can reach the ODPS/MaxCompute API for the given project.
  # Performs a lightweight signed GET on /projects/:project to verify credentials/endpoint.
  def connect
    validate!
    path = "/projects/#{escape(project_name)}"
    res = signed_request("GET", path)
    res.is_a?(Net::HTTPSuccess)
  end

  # Returns an array of table names in the project by calling ODPS REST: GET /projects/:project/tables
  def list_tables
    validate!
    path = "/projects/#{escape(project_name)}/tables"
    res = signed_request("GET", path, headers: { "Accept" => "application/xml" })

    unless res.is_a?(Net::HTTPSuccess)
      raise "ODPS list tables failed: #{res.code} #{res.message} #{res.body&.slice(0, 300)}"
    end

    body = res.body.to_s
    parse_tables(body)
  end

  # Backwards compatibility with any previous call sites
  alias_method :list_projects, :list_tables

  private

  def validate!
    raise ArgumentError, "Missing project name" if project_name.empty?
    raise ArgumentError, "Missing access_id" if access_id.empty?
    raise ArgumentError, "Missing access_secret" if access_secret.empty?
    raise ArgumentError, "Missing endpoint" if endpoint.empty?
  end

  def parse_tables(body)
    names = []

    # Try XML (default ODPS format)
    begin
      doc = REXML::Document.new(body)
      REXML::XPath.each(doc, "//Table/Name") { |n| names << n.text.to_s }
      return names if names.any?
    rescue StandardError
      # ignore
    end

    # Try JSON fallback
    begin
      parsed = JSON.parse(body)
      if parsed.is_a?(Hash)
        if parsed["tables"].is_a?(Array)
          return parsed["tables"].map { |t| t.is_a?(Hash) ? (t["name"] || t["Name"]) : t.to_s }
        elsif parsed["Items"].is_a?(Array)
          return parsed["Items"].map { |t| t["name"] || t["Name"] || t.to_s }
        end
      end
    rescue JSON::ParserError
      # ignore
    end

    # Very lenient XML-ish fallback
    names = body.scan(/<Name>([^<]+)<\/Name>/i).flatten.uniq
    names
  end

  # Perform a signed ODPS REST request (Authorization: ODPS <AK>:<Signature>)
  # Signature format:
  # StringToSign = HTTP-VERB + "\n" + Content-MD5 + "\n" + Content-Type + "\n" + Date + "\n" + CanonicalizedHeaders + CanonicalizedResource
  # We use standard "Date" header and include x-odps-* headers in the canonicalized headers.
  # For better compatibility with different gateways, we also send x-odps-date with the same GMT value.
  def signed_request(method, path, body: "", content_type: "", headers: {})
    uri = build_uri(path)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = uri.scheme == "https"
    http.read_timeout = 30

    content_md5 = ""
    ct = content_type.to_s
    gmt = Time.now.httpdate # RFC1123 GMT

    # x-odps-* headers are signed and must be included in CanonicalizedHeaders
    x_headers = {
      "x-odps-project" => project_name,
      "x-odps-date" => gmt
    }

    canonicalized_headers = x_headers
      .select { |k, _| k.downcase.start_with?("x-odps-") }
      .map { |k, v| "#{k.downcase}:#{v.to_s.strip}\n" }
      .sort
      .join

    canonical_resource = canonicalize_resource(uri, path)

    string_to_sign = [
      method.upcase,
      content_md5,
      ct,
      gmt, # Standard Date header included in the signature
      canonicalized_headers + canonical_resource
    ].join("\n")

    signature = sign_hmac_sha1(access_secret, string_to_sign)
    auth_header = "ODPS #{access_id}:#{signature}"

    req = case method.upcase
          when "GET"   then Net::HTTP::Get.new(uri.request_uri)
          when "POST"  then Net::HTTP::Post.new(uri.request_uri)
          when "PUT"   then Net::HTTP::Put.new(uri.request_uri)
          when "DELETE" then Net::HTTP::Delete.new(uri.request_uri)
          else
            raise "Unsupported method #{method}"
          end

    req["Authorization"] = auth_header
    req["Date"] = gmt
    req["x-odps-date"] = gmt
    req["x-odps-project"] = project_name
    req["Content-Type"] = ct unless ct.empty?
    # Default to XML unless caller overrides
    req["Accept"] = headers.key?("Accept") ? headers["Accept"] : "application/xml"
    headers.each { |k, v| req[k] = v }

    req.body = body.to_s unless body.nil? || body.to_s.empty?

    response = http.request(req)

    # Raise helpful message on failure for UI display
    unless response.is_a?(Net::HTTPSuccess)
      msg = "HTTP #{response.code} #{response.message}"
      detail = response.body&.slice(0, 500)
      debug = "url=#{uri} method=#{method.upcase} date=#{gmt} canon_headers=#{canonicalized_headers.inspect} canon_resource=#{canonical_resource}"
      @last_error = "#{msg} | #{debug} | body: #{detail}"
      raise @last_error
    end

    response
  end

  def build_uri(path)
    base = endpoint.to_s.sub(%r{/\z}, "")
    # Ensure path begins with single leading slash
    p = path.start_with?("/") ? path : "/#{path}"
    URI.parse("#{base}#{p}")
  end

  # According to ODPS signature rules, CanonicalizedResource is the absolute path plus query canonicalization if needed.
  # For simple resources without query parameters we use the path only.
  def canonicalize_resource(uri, raw_path)
    path_only = raw_path.start_with?("/") ? raw_path : "/#{raw_path}"
    if uri.query.to_s.empty?
      path_only
    else
      # sort query params by key
      params = URI.decode_www_form(uri.query).sort_by { |k, _| k }
      "#{path_only}?#{URI.encode_www_form(params)}"
    end
  end

  def sign_hmac_sha1(secret, data)
    digest = OpenSSL::Digest.new("sha1")
    Base64.strict_encode64(OpenSSL::HMAC.digest(digest, secret, data))
  end

  def escape(s)
    URI.encode_www_form_component(s.to_s)
  end
end