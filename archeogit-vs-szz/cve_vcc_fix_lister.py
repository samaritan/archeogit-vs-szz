from cve_intake import get_all_cves, get_data
import csv

field_names = ["#", "CVE", "# Fixes", "Fix(s)", "# Contributors", "Contributor(s)"]


def get_fix_commits(cve):
    fix_commits = []
    for fix in cve["fixes"]:
        if fix["commit"] is None:
            continue
        fix_commits.append(fix["commit"])
    return fix_commits


def get_vcc_commits(cve):
    vcc_commits = []
    for vcc in cve["vccs"]:
        if vcc["commit"] is None:
            continue
        vcc_commits.append(vcc["commit"])
    return vcc_commits


def process_cves(cves_list):
    results = []
    count = 1
    for cve in cves_list:
        result = []
        print("Processing: " + cve)
        data = get_data(cve)
        vccs = get_vcc_commits(data)
        fixes = get_fix_commits(data)
        result.append(count)
        result.append(cve[:-4])
        result.append(len(fixes))
        result.append(fixes)
        result.append(len(vccs))
        result.append(vccs)
        results.append(result)
        count += 1
    print(results)
    return results


def write_to_csv(results):
    with open('results.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(field_names)
        writer.writerows(results)


if __name__ == '__main__':
    cves = get_all_cves()
    result_set = process_cves(cves)
    write_to_csv(result_set)

