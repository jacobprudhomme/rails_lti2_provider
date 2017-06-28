module RailsLti2Provider
  module ControllerHelpers

    def lti_authentication
      lti_message = IMS::LTI::Models::Messages::Message.generate(request.request_parameters)
      lti_message.launch_url = request.url

      # validate the launch
      secret = RailsLti2Provider::Tool.find_by_uuid(request.request_parameters['oauth_consumer_key']).shared_secret
      authenticator = IMS::LTI::Services::MessageAuthenticator.new(request.url, request.request_parameters, secret)
      raise RailsLti2Provider::LtiLaunch::Unauthorized.new(:invalid_signature) unless authenticator.valid_signature?

      @lti_launch = RailsLti2Provider::LtiLaunch.check_launch(lti_message)
    end

    def disable_xframe_header
      response.headers["X-FRAME-OPTIONS"] = 'ALLOWALL'
      #response.headers.except! 'X-Frame-Options'
    end

    def registration_request
      registration_request = IMS::LTI::Models::Messages::Message.generate(params)
      @registration = RailsLti2Provider::Registration.new(
          registration_request_params: registration_request.post_params,
          tool_proxy_json: RailsLti2Provider::ToolProxyRegistration.new(registration_request, self).tool_proxy.as_json
      )
      if registration_request.is_a? IMS::LTI::Models::Messages::ToolProxyReregistrationRequest
        @registration.tool = Tool.where(uuid: params['oauth_consumer_key']).first
        @registration.correlation_id = SecureRandom.hex(64)
      end
    end

    def register_proxy(registration)
      if registration.registration_request.is_a? IMS::LTI::Models::Messages::ToolProxyReregistrationRequest
        RailsLti2Provider::ToolProxyRegistration.reregister(registration, self)
      else
        RailsLti2Provider::ToolProxyRegistration.register(registration, self)
      end
    end

    def redirect_to_consumer(registration_result)
      url = registration_result[:return_url]
      url = add_param(url, 'tool_proxy_guid', registration_result[:tool_proxy_uuid])
      status = 'success'
      if registration_result[:status] != 'success'
        status = 'error'
      end
      url = add_param(url, 'status', status)
      redirect_to url
    end

    def add_param(url, param_name, param_value)
      uri = URI(url)
      params = URI.decode_www_form(uri.query || '') << [param_name, param_value]
      uri.query = URI.encode_www_form(params)
      uri.to_s
    end

  end
end
