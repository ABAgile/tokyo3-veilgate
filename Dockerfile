FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
LABEL org.opencontainers.image.title="Veilgate" \
      org.opencontainers.image.description="Secret-aware egress gateway for agent sandboxes" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --chown=nonroot:nonroot bin/veilgated /usr/local/bin/veilgated
COPY --chown=nonroot:nonroot LICENSE /licenses/veilgate/LICENSE

EXPOSE 8080 8081
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/veilgated"]
CMD ["serve"]
