module DeviseSamlAuthenticatable
  class DefaultIdpEntityIdReader
    def self.entity_id(params)
      if params[:SAMLRequest]
        ::RubySaml::SloLogoutrequest.new(
          params[:SAMLRequest],
          settings: Devise.saml_config,
          allowed_clock_drift: Devise.allowed_clock_drift_in_seconds,
        ).issuer
      elsif params[:SAMLResponse]
        response_xml = RubySaml::XML::Decoder.decode_message(params[:SAMLResponse])
        document = RubySaml::XML.safe_load_nokogiri(response_xml)
        issuer_response_nodes = document.xpath(
          "/p:Response/a:Issuer",
          RubySaml::Response::SAML_NAMESPACES
        )
        issuer_response_nodes.map(&:text).reject(&:empty?).first
      end
    end
  end
end
