#[macro_use]
extern crate clap;
extern crate itertools;
extern crate sepolrs;

use clap::ArgMatches;
use itertools::Itertools;
use sepolrs::policydb::feature::Feature;
use sepolrs::policydb::Policy;
use sepolrs::policydb::PolicyType;

fn run_subcommand<Runner>(name: &str, matches: &ArgMatches, policy: &Policy, subcmd_runner: Runner)
where
    Runner: FnOnce(&Policy, &ArgMatches),
{
    let args = matches.subcommand_matches(name).unwrap();
    subcmd_runner(policy, args)
}

fn main() {
    let mut app = clap_app!(seinspect =>
        (version: "1.0")
        (about: "A tool used to inspect and analyze SELinux policy")
        (@arg POLICY: -p --policy +takes_value "Use a custom policy path")
        (@subcommand info =>
            (about: "show high-level policy information")
        )
    );

    let matches = app.clone().get_matches();

    let policy_path = matches
        .value_of("POLICY")
        .unwrap_or("/sys/fs/selinux/policy");

    let policy = sepolrs::load_policy_from_file(policy_path).expect("Unable to parse policy");

    match matches.subcommand_name() {
        Some("info") => run_subcommand("info", &matches, &policy, show_policy_info),
        _ => app.print_help().unwrap(),
    };
}

fn show_policy_info(policy: &Policy, _args: &ArgMatches) {
    let ty_str = match policy.ty() {
        &PolicyType::Kernel(ref platform) => format!("{:#?} Kernel policy", platform),
        &PolicyType::Module {
            is_base_module: _,
            ref name,
            ref version,
        } => format!("Modular policy, {} v{}", name, version),
    };

    println!("Policy type: {}", ty_str);
    println!("Policy version: {}", policy.version());

    if policy.profile().supports(Feature::PolicyCapabilities) {
        let polcaps_str = policy
            .polcaps()
            .all()
            .iter()
            .map(|p| p.to_string())
            .join(", ");

        println!("Policy capabilities: {}", polcaps_str);
    }
}
