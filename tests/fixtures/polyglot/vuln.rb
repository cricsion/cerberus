require 'yaml'
class UsersController < ApplicationController
  def show
    @users = User.where("name = '#{params[:name]}'")
    data = YAML.load(params[:blob])
    render plain: eval(params[:expr])
  end
end
