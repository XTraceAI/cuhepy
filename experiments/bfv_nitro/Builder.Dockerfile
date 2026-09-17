# Local Linux EIF builder; no AWS credentials, NSM device or cloud access needed.
# The Docker socket is needed only to export the selected local service image.
FROM amazonlinux:2023@sha256:181f98c48832fe926f8ca3b6ffeafcce128e96e77b93d08fbe9a9bc9403ce284
RUN dnf install -y aws-nitro-enclaves-cli-1.4.5-0.amzn2023 aws-nitro-enclaves-cli-devel-1.4.5-0.amzn2023 && dnf clean all
RUN nitro-cli --version
ENTRYPOINT ["nitro-cli"]
