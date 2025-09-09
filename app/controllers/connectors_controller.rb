class ConnectorsController < ApplicationController
  def new
    # Instantiate with optional keyword args to avoid ArgumentError if class isn't reloaded yet
    @connector = DataworksConnector.new(
      project_name: "",
      access_id: "",
      access_secret: "",
      endpoint: ""
    )
    @tables = [] # nothing to show initially
  end
 
  def create
    @connector = DataworksConnector.new(
      project_name: params[:dataworks_connector_project_name],
      access_id: params[:dataworks_connector_access_id],
      access_secret: params[:dataworks_connector_access_secret],
      endpoint: params[:dataworks_connector_endpoint]
    )
 
    begin
      if @connector.connect
        @tables = @connector.list_tables
        flash.now[:notice] = "Connected to #{params[:dataworks_connector_endpoint]} project=#{params[:dataworks_connector_project_name]}. Listed #{@tables.length} tables."
      else
        @tables = []
        flash.now[:alert] = "Failed to connect to DataWorks (unexpected result)."
      end
    rescue => e
      @tables = []
      flash.now[:alert] = "Connection failed: #{e.message}"
    end
 
    render :new
  end
end