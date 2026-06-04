sleep 10

aws cloudfront list-distributions \
  --profile CFG-NOC-L2-System-Administrator-cfg-network-services-prod-foundation-account \
  --query "DistributionList.Items[?DomainName=='d7lg9vdd9r6gn.cloudfront.net'].[Id,DomainName,Status,Enabled]" \
  --output text




--------------------

sleep 5
for profile in $(aws configure list-profiles); do
  id=$(aws cloudfront list-distributions --profile "$profile" \
    --query "DistributionList.Items[?DomainName=='d7lg9vdd9r6gn.cloudfront.net'].Id" \
    --output text 2>/dev/null)
  if [ -n "$id" ] && [ "$id" != "None" ]; then
    echo ">>> Distribution in $profile : $id"
  fi
done
