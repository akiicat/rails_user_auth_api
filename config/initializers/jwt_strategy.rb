module Devise
  module Strategies
    class JWT < Base
      def valid?
        request.headers["Authorization"].present?
      end

      def authenticate!
        token   = request.headers.fetch("Authorization", "").split(" ").last
        payload = JsonWebToken.decode(token)
        success! User.find(payload["sub"])
      rescue ::JWT::ExpiredSignature
        fail! "Auth token has expired"
      rescue ::JWT::DecodeError
        fail! "Auth token is invalid"
      end
    end
  end
end
