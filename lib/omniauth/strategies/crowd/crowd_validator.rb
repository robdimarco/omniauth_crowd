require 'nokogiri'
require 'net/http'
require 'net/https'

module OmniAuth
  module Strategies
    class Crowd
      class CrowdValidator
        AUTHENTICATION_REQUEST_BODY = "<password><value>%s</value></password>"
        def initialize(configuration, username, password)
          @configuration, @username, @password = configuration, username, password
          @authentiction_uri = URI.parse(@configuration.authentication_url(@username))
          @user_group_uri    = @configuration.include_users_groups? ? URI.parse(@configuration.user_group_url(@username)) : nil
        end

        def user_info
          user_info_hash = retrieve_user_info!
          if user_info_hash && @configuration.include_users_groups?
            add_user_groups(user_info_hash)
          else
            nil
          end
        end

        private
        def add_user_groups(user_info_hash)
          response, body = make_user_group_request
          unless response.code.to_i != 200 || body.nil? || body == '' 
            doc = Nokogiri::XML(body)
            user_info_hash["groups"] = doc.xpath("//groups/group/@name").map(&:to_s)
          end
          user_info_hash
        end
        
        def retrieve_user_info!
          response, body = make_authorization_request
          unless response.code.to_i != 200 || body.nil? || body == '' 
            doc = Nokogiri::XML(body)
            {
              "user" => doc.xpath("//user/@name").to_s,
              "name" => doc.xpath("//user/display-name/text()").to_s,
              "first_name" => doc.xpath("//user/first-name/text()").to_s,
              "last_name" => doc.xpath("//user/last-name/text()").to_s,
              "email" => doc.xpath("//user/email/text()").to_s
            }
          else
            nil
          end
        end
        
        def make_user_group_request
          http = Net::HTTP.new(@user_group_uri.host, @user_group_uri.port)
          http.use_ssl = @user_group_uri.port == 443 || @user_group_uri.instance_of?(URI::HTTPS)
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl? && @configuration.disable_ssl_verification?
          http.start do |c|
            req = Net::HTTP::Get.new("#{@user_group_uri.path}?#{@user_group_uri.query}")
            req.basic_auth @configuration.crowd_application_name, @configuration.crowd_password
            req.add_field 'Content-Type', 'text/xml'
            http.request(req)
          end
        end
        
        def make_authorization_request 
          http = Net::HTTP.new(@authentiction_uri.host, @authentiction_uri.port)
          http.use_ssl = @authentiction_uri.port == 443 || @authentiction_uri.instance_of?(URI::HTTPS)
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl? && @configuration.disable_ssl_verification?
          http.start do |c|
            req = Net::HTTP::Post.new("#{@authentiction_uri.path}?#{@authentiction_uri.query}")
            req.body = AUTHENTICATION_REQUEST_BODY % @password
            req.basic_auth @configuration.crowd_application_name, @configuration.crowd_password
            req.add_field 'Content-Type', 'text/xml'
            http.request(req)
          end
        end
      end
    end
  end
end
