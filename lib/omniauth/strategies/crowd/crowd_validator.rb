require 'nokogiri'
require 'net/http'
require 'net/https'

module OmniAuth
  module Strategies
    class Crowd
      class CrowdValidator
        def initialize(configuration, username, password)
          @configuration, @username, @password = configuration, username, password
          @uri = URI.parse(@configuration.authentication_url(@username))
        end

        def user_info
          if is_user_authorized?
            parse_user_info
          else
            nil
          end
        end

        private
        def parse_user_info
          return nil if @body.nil? || @body == ''
          doc = Nokogiri::XML(@body)
          return nil if doc.nil?
          {
            "user" => doc.xpath("//user/@name").to_s,
            "name" => doc.xpath("//user/display-name/text()").to_s,
            "first_name" => doc.xpath("//user/first-name/text()").to_s,
            "last_name" => doc.xpath("//user/last-name/text()").to_s,
            "email" => doc.xpath("//user/email/text()").to_s
          }
        end
        AUTHENTICATION_REQUEST_BODY = "<password><value><![CDATA[%s]]></value></password>"
        def is_user_authorized?
          http = Net::HTTP.new(@uri.host, @uri.port)
          http.use_ssl = @uri.port == 443 || @uri.instance_of?(URI::HTTPS)
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl? && @configuration.disable_ssl_verification?
          http.start do |c|
            req = Net::HTTP::Post.new("#{@uri.path}?#{@uri.query}")
            req.body = AUTHENTICATION_REQUEST_BODY % @password
            req.basic_auth @configuration.crowd_application_name, @configuration.crowd_password
            req.add_field 'Content-Type', 'text/xml'
            @response, @body = http.request(req)
            @response.code.to_i == 200
          end
        end
      end
    end
  end
end
