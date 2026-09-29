# Deploying GodShield API to the cloud

The local stack runs from `docker-compose.yml`. These are the two cloud
targets for the GodShield API (`docker/Dockerfile.godshield`, port 8090).

## Kubernetes — `deploy/k8s/`

    kubectl apply -f deploy/k8s/namespace.yaml
    kubectl -n godshield create secret generic godshield-api \
      --from-literal=GODSHIELD_ADMIN_TOKEN=$(openssl rand -hex 32)
    # set image: ghcr.io/<owner>/godshield-api:<git sha> in deployment.yaml
    kubectl apply -f deploy/k8s/deployment.yaml
    kubectl apply -f deploy/k8s/ingress.yaml      # after editing the host

Needs an nginx ingress controller and cert-manager with a
`letsencrypt-prod` ClusterIssuer.

## AWS — `deploy/terraform/`

ECS Fargate in private subnets, behind an HTTPS Application Load Balancer
in public subnets, images in ECR tagged by git SHA, CPU autoscaling 3–20.

    cd deploy/terraform
    terraform init
    terraform apply \
      -var 'vpc_id=vpc-…' \
      -var 'public_subnet_ids=["subnet-…","subnet-…"]' \
      -var 'private_subnet_ids=["subnet-…","subnet-…"]' \
      -var 'image_tag=<git sha>' \
      -var 'certificate_arn=arn:aws:acm:…'

Push the image to the `ecr_repository_url` output before the service
starts.

The gateway's rate windows and audit chain are per process. Verification
and scanning scale out as they are; for one shared audit chain across
replicas, run a single task or add shared storage first.
