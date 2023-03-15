use super::{Attestation, TeeEvidenceParsedClaim, Verifier};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;
use vtpm_snp::certs::{get_chain_from_amd, get_vcek_from_amd};
use vtpm_snp::hcl::HclReportWithRuntimeData;
use vtpm_snp::report::Validateable;
use vtpm_snp::vtpm::{Quote, VerifyVTpmQuote};

#[derive(Serialize, Deserialize)]
struct VtpmSnpEvidence {
    quote: Quote,
    hcl_report: HclReportWithRuntimeData,
}

#[derive(Default)]
pub struct SevSnpVtpm;

#[async_trait]
impl Verifier for SevSnpVtpm {
    async fn evaluate(
        &self,
        nonce: String,
        _attestation: &Attestation,
    ) -> Result<TeeEvidenceParsedClaim> {
        let evidence = serde_json::from_str::<VtpmSnpEvidence>(&_attestation.tee_evidence)
            .context("Failed to deserialize vTPM SEV-SNP evidence")?;

        verify_vtpm_quote(&evidence.hcl_report, &evidence.quote, nonce.as_bytes())?;
        verify_snp_report(&evidence.hcl_report)?;

        let claim = build_claim(&evidence);
        Ok(claim)
    }
}

fn build_claim(evidence: &VtpmSnpEvidence) -> TeeEvidenceParsedClaim {
    let report = evidence.hcl_report.snp_report();
    let tcb = report.reported_tcb;
    let claims_map = json!({ "tcb": tcb });
    claims_map as TeeEvidenceParsedClaim
}

fn verify_snp_report(report: &HclReportWithRuntimeData) -> Result<()> {
    let snp_report = report.snp_report();
    let vcek = get_vcek_from_amd(&snp_report)?;
    let cert_chain = get_chain_from_amd()?;

    cert_chain.validate()?;
    vcek.validate(&cert_chain)?;
    snp_report.validate(&vcek)?;

    Ok(())
}

fn verify_vtpm_quote(report: &HclReportWithRuntimeData, quote: &Quote, nonce: &[u8]) -> Result<()> {
    let ak_pub = report.get_attestation_key()?;

    ak_pub
        .verify_quote(quote, Some(nonce))
        .context("Failed to verify vTPM quote")?;

    Ok(())
}
