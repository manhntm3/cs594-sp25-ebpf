use anyhow::{anyhow, Context as _};
use aya_build::cargo_metadata;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_packages: Vec<_> = packages
        .into_iter()
        .filter(|cargo_metadata::Package { name, .. }| {
            name == "xdp-filter-ebpf" || name == "tc-filter-ebpf"
        })
        .collect();

    if ebpf_packages.is_empty() {
        return Err(anyhow!("No eBPF packages found"));
    }

    aya_build::build_ebpf(ebpf_packages)
}
