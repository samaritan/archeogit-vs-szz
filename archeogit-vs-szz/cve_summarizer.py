import requests
from cve_intake import get_all_cves, get_data

# Change this to the github repo of the vulnerabilties
GITHUB_REPOSITORY = "https://github.com/apache/struts/"


def has_fix(cve):
    for fix in cve["fixes"]:
        if fix["commit"] is not None:
            return True
    return False


def has_vcc(cve):
    for vcc in cve["vccs"]:
        if vcc["commit"] is not None:
            return True
    return False


def invalid_fix_count(cve):
    invalid_count = 0
    for fix in cve["fixes"]:
        if fix["commit"] is None:
            continue
        fix_commit = fix["commit"]
        url = GITHUB_REPOSITORY + "/commit/" + fix_commit
        response = requests.get(url)
        if response.status_code == 404:
            invalid_count += 1
    return invalid_count


def invalid_vcc_count(cve):
    invalid_count = 0
    for vcc in cve["vccs"]:
        if vcc["commit"] is None:
            continue
        vcc_commit = vcc["commit"]
        url = GITHUB_REPOSITORY + "/commit/" + vcc_commit
        response = requests.get(url)
        if response.status_code == 404:
            invalid_count += 1
    return invalid_count


def has_both_vcc_and_fix(cve):
    return has_fix(cve) and has_vcc(cve)


def build_summary():
    summary = dict()
    summary["Number of vulnerabilities"] = 0
    summary["Number of vulnerabilities with fixes"] = 0
    summary["Number of invalid fix commits"] = 0
    summary["Number of vulnerabilties with both vcc and fix"] = 0
    summary["Number of invalid vcc commits"] = 0
    return summary


def process_cves(cves_list):
    summary = build_summary()
    for cve in cves_list:
        print("Processing: " + cve)
        data = get_data(cve)
        if has_fix(data):
            summary["Number of vulnerabilities with fixes"] += 1

        if has_both_vcc_and_fix(data):
            summary["Number of vulnerabilties with both vcc and fix"] += 1

        summary["Number of invalid fix commits"] += invalid_fix_count(data)
        summary["Number of invalid vcc commits"] += invalid_vcc_count(data)

        summary["Number of vulnerabilities"] += 1

    for k, v in summary.items():
        print(k + ": " + str(v))


if __name__ == '__main__':
    files = get_all_cves()
    process_cves(files)
