"""
Deterministic fictional organization: domain, network map, hosts, users.

Everything here is derived from rng_env only, so the environment is stable
for a given seed regardless of --target-size or --days.
"""

FIRST_NAMES = [
    "Dana", "Omer", "Maya", "Itai", "Noa", "Yossi", "Lior", "Tal",
    "Roni", "Guy", "Shira", "Eyal", "Yael", "Nadav", "Michal", "Ori",
]
LAST_NAMES = [
    "Cohen", "Levi", "Mizrahi", "Peretz", "Biton", "Azoulay", "Katz",
    "Friedman", "Shapiro", "Golan", "Har-Even", "Barak", "Sasson", "Nir",
]
DEPARTMENTS = ["finance", "sales", "hr", "it", "ops", "engineering"]

DOMAIN_POOL = ["corptrust.local", "meridianlogix.local", "brightfield.local", "novacore.local"]
ORG_NAME_MAP = {
    "corptrust.local": "CorpTrust Ltd.",
    "meridianlogix.local": "Meridian Logix",
    "brightfield.local": "Brightfield Partners",
    "novacore.local": "NovaCore Industries",
}


def _rand_ip(rng, third_octet):
    return "10.42.{}.{}".format(third_octet, rng.randint(10, 250))


def build_environment(rng_env, num_workstations=6):
    domain = rng_env.choice(DOMAIN_POOL)
    org_name = ORG_NAME_MAP[domain]

    first_names = list(FIRST_NAMES)
    last_names = list(LAST_NAMES)
    rng_env.shuffle(first_names)
    rng_env.shuffle(last_names)

    num_users = rng_env.randint(6, 10)
    users = []
    used_logins = set()
    for i in range(num_users):
        fn = first_names[i % len(first_names)]
        ln = last_names[i % len(last_names)]
        login = (fn[0] + ln).lower()
        while login in used_logins:
            login = login + str(rng_env.randint(2, 9))
        used_logins.add(login)
        users.append({
            "username": login,
            "full_name": "{} {}".format(fn, ln),
            "department": rng_env.choice(DEPARTMENTS),
            "is_admin": False,
            "is_service": False,
        })

    # At least one genuine (non-service) admin account is required by the
    # scenario builder for credential reuse / lateral movement.
    human_admin_names = ["adm-jsmith", "adm-mrogers"]
    service_names = ["svc-backup", "svc-scanner"]
    users.append({
        "username": rng_env.choice(human_admin_names),
        "full_name": "IT Administration",
        "department": "it",
        "is_admin": True,
        "is_service": False,
    })
    if rng_env.random() < 0.6:
        name = rng_env.choice(service_names)
        users.append({
            "username": name,
            "full_name": "IT Administration",
            "department": "it",
            "is_admin": False,
            "is_service": True,
        })

    hosts = []

    fw_ip = _rand_ip(rng_env, 1)
    hosts.append({
        "hostname": "FGT-EDGE01",
        "fqdn": None,
        "ip": fw_ip,
        "role": "firewall",
        "os": "FortiOS 7.4",
        "primary_user": None,
    })

    dc_host = "DC01"
    dc_ip = _rand_ip(rng_env, 5)
    hosts.append({
        "hostname": dc_host,
        "fqdn": "{}.{}".format(dc_host, domain),
        "ip": dc_ip,
        "role": "domain_controller",
        "os": "Windows Server 2022",
        "primary_user": None,
    })

    fs_host = "FS01"
    fs_ip = _rand_ip(rng_env, 5)
    while fs_ip == dc_ip:
        fs_ip = _rand_ip(rng_env, 5)
    hosts.append({
        "hostname": fs_host,
        "fqdn": "{}.{}".format(fs_host, domain),
        "ip": fs_ip,
        "role": "file_server",
        "os": "Windows Server 2022",
        "primary_user": None,
    })

    ordinary_users = [u for u in users if not u["is_admin"] and not u["is_service"]]
    used_ws_ips = {dc_ip, fs_ip}
    for i in range(num_workstations):
        wname = "WKS{:02d}".format(i + 1)
        wip = _rand_ip(rng_env, 20)
        while wip in used_ws_ips:
            wip = _rand_ip(rng_env, 20)
        used_ws_ips.add(wip)
        primary_user = ordinary_users[i % len(ordinary_users)]["username"]
        os_choice = rng_env.choice(["Windows 10 22H2", "Windows 11 23H2"])
        hosts.append({
            "hostname": wname,
            "fqdn": "{}.{}".format(wname, domain),
            "ip": wip,
            "role": "workstation",
            "os": os_choice,
            "primary_user": primary_user,
        })

    machine_guid_map = {}
    for h in hosts:
        if h["role"] == "firewall":
            continue
        machine_guid_map[h["hostname"]] = "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}".format(
            rng_env.getrandbits(32), rng_env.getrandbits(16), rng_env.getrandbits(16),
            rng_env.getrandbits(16), rng_env.getrandbits(48),
        )

    return {
        "domain": domain,
        "org_name": org_name,
        "hosts": hosts,
        "users": users,
        "machine_guids": machine_guid_map,
        "dc_hostname": dc_host,
        "file_server_hostname": fs_host,
        "firewall_hostname": "FGT-EDGE01",
    }


def host_by_name(environment, hostname):
    for h in environment["hosts"]:
        if h["hostname"] == hostname:
            return h
    raise KeyError(hostname)


def user_by_name(environment, username):
    for u in environment["users"]:
        if u["username"] == username:
            return u
    raise KeyError(username)


def workstation_hosts(environment):
    return [h for h in environment["hosts"] if h["role"] == "workstation"]
