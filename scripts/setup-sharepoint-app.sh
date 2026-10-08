#!/usr/bin/env bash
set -euo pipefail

output_dir="${1:-./secrets/sharepoint}"
common_name="${2:-RTM SharePoint App}"
certificate_path="${output_dir}/sharepoint-app.crt"
private_key_path="${output_dir}/sharepoint-app.key"

if [[ -e "${certificate_path}" || -e "${private_key_path}" ]]; then
  echo "Refusing to overwrite an existing certificate or key in ${output_dir}." >&2
  exit 1
fi

mkdir -p "${output_dir}"
chmod 700 "${output_dir}"
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 730 \
  -subj "/CN=${common_name}" \
  -keyout "${private_key_path}" \
  -out "${certificate_path}"
chmod 600 "${private_key_path}"
chmod 644 "${certificate_path}"

thumbprint="$(openssl x509 -in "${certificate_path}" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :)"
expiry="$(openssl x509 -in "${certificate_path}" -noout -enddate | cut -d= -f2-)"

echo
echo "Certificate created:"
echo "  Public certificate: ${certificate_path}"
echo "  Private key:        ${private_key_path}"
echo "  SHA-1 thumbprint:   ${thumbprint}"
echo "  Expires:            ${expiry}"
echo
echo "Entra app registration:"
echo "  1. Create one multi-tenant app registration."
echo "  2. Upload ${certificate_path} under Certificates & secrets > Certificates."
echo "  3. Add Microsoft Graph APPLICATION permissions:"
echo "       Sites.Read.All"
echo "       Sites.ReadWrite.All"
echo "       GroupMember.Read.All"
echo "       User.Read.All"
echo "  4. Add Office 365 SharePoint Online APPLICATION permission:"
echo "       Sites.FullControl.All"
echo "  5. Grant admin consent in every connected tenant."
echo
echo "RTM environment:"
echo "  RTM_SHAREPOINT_CLIENT_ID=<application-client-id>"
echo "  RTM_SHAREPOINT_CERTIFICATE_PATH=${certificate_path}"
echo "  RTM_SHAREPOINT_PRIVATE_KEY_PATH=${private_key_path}"
echo
echo "For each RTM tenant, enter its https://<tenant>-admin.sharepoint.com URL"
echo "and run Permission Preflight. Keep the private key out of source control."
