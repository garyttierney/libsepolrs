#[macro_use]
extern crate clap;
extern crate itertools;
extern crate sepolrs;

use clap::ArgMatches;
use itertools::Itertools;
use sepolrs::policydb::profile::Feature;
use sepolrs::policydb::symtable::Symbol;
use sepolrs::policydb::Policy;
use sepolrs::policydb::PolicyType;

mod inspect;

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
        (@arg POLICY: -p --policy +takes_value "Override the path to the binary policy file")
        (@subcommand info =>
            (about: "Show high-level policy information")
            (@arg SHOW_BOOLEANS: --booleans "Show conditional booleans listed in the policy")
            (@arg SHOW_COMMONS: --common "Show common security classes listed in the policy")
            (@arg SHOW_USERS: --users "Show users listed in the policy")
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

fn show_policy_info(policy: &Policy, args: &ArgMatches) {
    if args.is_present("SHOW_BOOLEANS") {
        show_policy_boolean_info(policy);
    } else if args.is_present("SHOW_COMMONS") {
        show_policy_common_info(&policy)
    } else if args.is_present("SHOW_USERS") {
        show_policy_user_info(&policy);
    } else {
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

        println!();
        println!("Classes: {}", policy.classes().len());
        println!("Roles: {}", policy.roles().len());
        println!("Users: {}", policy.users().len());
    }
}

fn show_policy_user_info(policy: &Policy) {
    for user in policy.users().all() {
        println!("User: {}", user.name());
        println!("\t Default MLS Level: {:#?}", user.default_level());
        println!("\t MLS Range: {:#?}", user.default_level());
    }
}

fn show_policy_common_info(policy: &Policy) {
    for common in policy.common_classes().all() {
        let common_name = common.name();
        let permission_names = common
            .permissions()
            .all()
            .map(|p| format!("\t{}", p.name()))
            .join(",\n");

        println!("{} {{ \n {} \n}}", common_name, permission_names);
    }
}

fn show_policy_boolean_info(policy: &Policy) {
    for boolean in policy.booleans().all() {
        println!("{} [{}]", boolean.name(), boolean.is_toggled());
    }
}
