//! Reads the names a tunnel's certificate request asks for, after checking its signature.

use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The subject's common name.
    pub hostname: String,
    /// The DNS subject alternative names without duplicates, or the common name when there are none.
    pub identifiers: Vec<String>,
}

/// Accepts PEM or base64 DER. `None` for anything that does not parse or verify.
pub fn parse(csr: &str) -> Option<Request> {
    let der = crate::acme::pem_der(csr)?;
    let (_, request) = X509CertificationRequest::from_der(&der).ok()?;
    request.verify_signature().ok()?;
    let info = &request.certification_request_info;
    let common_names: Vec<String> = info
        .subject
        .iter_common_name()
        .filter_map(|name| name.as_str().ok().map(str::to_owned))
        .collect();
    // The Worker stringified the list of CN values, which joins them with commas.
    let hostname = common_names.join(",");
    let mut identifiers: Vec<String> = Vec::new();
    for extension in request.requested_extensions().into_iter().flatten() {
        if let ParsedExtension::SubjectAlternativeName(names) = extension {
            for name in &names.general_names {
                if let GeneralName::DNSName(name) = name
                    && !identifiers.iter().any(|existing| existing == name)
                {
                    identifiers.push((*name).to_owned());
                }
            }
        }
    }
    if identifiers.is_empty() {
        identifiers.push(hostname.clone());
    }
    Some(Request {
        hostname,
        identifiers,
    })
}

/// Whether `id` can name a tunnel: one DNS label of lowercase letters, digits and inner hyphens.
pub fn valid_tunnel_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-'
}

/// The only names a tunnel's certificate may cover: `<id>.<domain>` (always) and `*.<id>.<domain>`.
/// `Err` says what is wrong. Every certificate a tunnel gets is checked here right before it is ordered, so
/// nothing (an imported record, a stored job) can make the server order one for another name, the domain
/// itself, or another tunnel.
pub fn check_tunnel_names(id: &str, domain: &str, identifiers: &[String]) -> Result<(), String> {
    if !valid_tunnel_id(id) {
        return Err(format!("{id:?} is not a tunnel ID"));
    }
    let hostname = format!("{id}.{domain}");
    let wildcard = format!("*.{hostname}");
    if identifiers.is_empty() || identifiers.len() > 2 {
        return Err(format!("{} names requested", identifiers.len()));
    }
    for (index, identifier) in identifiers.iter().enumerate() {
        if !identifier.eq_ignore_ascii_case(&hostname)
            && !identifier.eq_ignore_ascii_case(&wildcard)
        {
            return Err(format!("{identifier:?} is not a name of tunnel {id}"));
        }
        if identifiers[..index]
            .iter()
            .any(|earlier| earlier.eq_ignore_ascii_case(identifier))
        {
            return Err(format!("{identifier:?} requested twice"));
        }
    }
    if !identifiers
        .iter()
        .any(|identifier| identifier.eq_ignore_ascii_case(&hostname))
    {
        return Err(format!("{hostname} is not requested"));
    }
    Ok(())
}

/// [`check_tunnel_names`], and that `csr` is a valid request for exactly those names (its common name the
/// tunnel's hostname).
pub fn check_tunnel_request(
    id: &str,
    domain: &str,
    identifiers: &[String],
    csr: &str,
) -> Result<(), String> {
    check_tunnel_names(id, domain, identifiers)?;
    let request = parse(csr).ok_or_else(|| "the CSR does not parse or verify".to_owned())?;
    if !request
        .hostname
        .eq_ignore_ascii_case(&format!("{id}.{domain}"))
    {
        return Err(format!(
            "the CSR is for {:?}, not tunnel {id}",
            request.hostname
        ));
    }
    let same = request.identifiers.len() == identifiers.len()
        && request.identifiers.iter().all(|name| {
            identifiers
                .iter()
                .any(|identifier| identifier.eq_ignore_ascii_case(name))
        });
    if !same {
        return Err(format!(
            "the CSR asks for {:?}, not {identifiers:?}",
            request.identifiers
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn only_a_tunnels_own_names_pass() {
        let names = |list: &[&str]| {
            list.iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>()
        };
        let domain = "opentunnel.test";
        assert!(check_tunnel_names("abc", domain, &names(&["abc.opentunnel.test"])).is_ok());
        assert!(
            check_tunnel_names(
                "abc",
                domain,
                &names(&["abc.opentunnel.test", "*.abc.opentunnel.test"])
            )
            .is_ok()
        );
        for bad in [
            names(&["opentunnel.test", "*.opentunnel.test"]),
            names(&["opentunnel.test"]),
            names(&["*.opentunnel.test"]),
            names(&["xyz.opentunnel.test"]),
            names(&["abc.opentunnel.test", "xyz.opentunnel.test"]),
            names(&["*.abc.opentunnel.test"]),
            names(&["abc.opentunnel.test", "abc.opentunnel.test"]),
            names(&["a.abc.opentunnel.test", "abc.opentunnel.test"]),
            names(&["abc.opentunnel.test.evil.com"]),
            names(&[]),
        ] {
            assert!(check_tunnel_names("abc", domain, &bad).is_err(), "{bad:?}");
        }
        for id in ["", "ABC", "a.b", "-a", "a-", "*", &"a".repeat(64)] {
            assert!(
                check_tunnel_names(id, domain, &[format!("{id}.{domain}")]).is_err(),
                "{id}"
            );
        }

        let (csr, _) = tunnel_csr("abc.opentunnel.test");
        let both = names(&["abc.opentunnel.test", "*.abc.opentunnel.test"]);
        assert!(check_tunnel_request("abc", domain, &both, &csr).is_ok());
        // The CSR must ask for exactly the names, for this tunnel.
        assert!(check_tunnel_request("abc", domain, &both[..1], &csr).is_err());
        assert!(
            check_tunnel_request("xyz", domain, &names(&["xyz.opentunnel.test"]), &csr).is_err()
        );
        let (apex, _) = tunnel_csr("opentunnel.test");
        assert!(check_tunnel_request("abc", domain, &both, &apex).is_err());
        assert!(check_tunnel_request("abc", domain, &both, "garbage").is_err());
    }

    /// A tunnel CSR as the clients make it: CN and SANs for the hostname and its wildcard.
    pub(crate) fn tunnel_csr(hostname: &str) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec![hostname.into(), format!("*.{hostname}")]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, hostname);
        (
            params.serialize_request(&key).unwrap().pem().unwrap(),
            key.serialize_pem(),
        )
    }

    #[test]
    fn reads_tunnel_requests() {
        let (csr, _) = tunnel_csr("abc.opentunnel.test");
        assert_eq!(
            parse(&csr),
            Some(Request {
                hostname: "abc.opentunnel.test".into(),
                identifiers: vec!["abc.opentunnel.test".into(), "*.abc.opentunnel.test".into()]
            })
        );
    }

    #[test]
    fn rejects_garbage_and_bad_signatures() {
        assert_eq!(parse("garbage"), None);
        let (csr, _) = tunnel_csr("abc.opentunnel.test");
        let mut der = crate::acme::pem_der(&csr).unwrap();
        let last = der.len() - 1;
        der[last] ^= 1;
        use base64::Engine;
        let tampered = base64::engine::general_purpose::STANDARD.encode(der);
        assert_eq!(parse(&tampered), None);
    }
}
