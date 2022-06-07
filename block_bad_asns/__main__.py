import requests
import csv
import os
import json


def find_rule(asn: str):
    zone_id = os.environ['CF_ZONE_ID']
    api_token = os.environ['CF_API_TOKEN']
    res = requests.get(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules",
        headers={'Authorization': f"Bearer {api_token}"},
        params={
            'configuration.target': 'asn',
            'configuration.value': f"AS{asn}"
        })
    j = res.json()
    if j['success'] == True:
        return j['result'][0]['id']
    else:
        raise RuntimeError(f"Error finding rule for AS{asn}:", j['errors'])


def block_asn(asn: str) -> None:
    zone_id = os.environ['CF_ZONE_ID']
    api_token = os.environ['CF_API_TOKEN']
    data = {
        'mode': 'block',
        'configuration': {
            'target': 'asn',
            'value': f"AS{asn}"
        },
    }
    res = requests.post(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules",
        json=data,
        headers={'Authorization': f"Bearer {api_token}"})
    j = res.json()
    if j['success'] == False:
        if len(j['errors']) > 0 and j['errors'][0]['code'] == 10009:
            # Rule already exists.
            rule_id = find_rule(asn)
            # Edit rule instead to set it to block the ASN instead of whatever it was doing before (e.g., `js_challenge`).
            res = requests.patch(
                f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/access_rules/rules/{rule_id}",
                json=data,
                headers={'Authorization': f"Bearer {api_token}"})
            j = res.json()
            if j['success'] == False:
                print(f"Blocking AS{asn} failed with error:")
                print(j['errors'])
        elif len(j['errors']) > 0:
            print(f"Blocking AS{asn} failed with error:")
            print(j['errors'])
        else:
            print(f"Blocking AS{asn} failed with error code: {res.status}")


if __name__ == '__main__':
    with open('bad-asn-list.csv') as csvfile:
        rdr = csv.DictReader(csvfile)
        for row in rdr:
            print('Blocking', row['ASN'], row['Entity'], '...')
            block_asn(row['ASN'])
