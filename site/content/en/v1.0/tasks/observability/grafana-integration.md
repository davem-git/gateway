---
title: "Visualising metrics using Grafana"
---

Envoy Gateway provides support for exposing Envoy Proxy metrics to a Prometheus instance.
This guide shows you how to visualise the metrics exposed to prometheus using grafana.

## Prerequisites

Follow the steps from the [Quickstart](../../quickstart) to install Envoy Gateway and the example manifest.
Before proceeding, you should be able to query the example backend using HTTP.

Follow the steps from the [Proxy Observability](../proxy-observability#Metrics) to enable prometheus metrics.

[Prometheus](https://prometheus.io) is used to scrape metrics from the Envoy Proxy instances. Install Prometheus:

```shell
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm upgrade --install prometheus prometheus-community/prometheus -n monitoring --create-namespace
```

[Grafana](https://grafana.com/grafana/) is used to visualise the metrics exposed by the envoy proxy instances.
Install Grafana:

```shell
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
helm upgrade --install grafana grafana/grafana -f https://raw.githubusercontent.com/envoyproxy/gateway/latest/examples/grafana/helm-values.yaml -n monitoring --create-namespace
```

Expose endpoints:

```shell
GRAFANA_IP=$(kubectl get svc grafana -n monitoring -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
```

## Connecting Grafana with Prometheus datasource

To visualise metrics from Prometheus, we have to connect Grafana with Prometheus. If you installed Grafana from the command
from prerequisites sections, the prometheus datasource should be already configured.

You can also add the data source manually by following the instructions from [Grafana Docs](https://grafana.com/docs/grafana/latest/datasources/prometheus/configure/).

## Accessing Grafana

You can access the Grafana instance by visiting `http://{GRAFANA_IP}`, derived in prerequisites.

To log in to Grafana, use the credentials `admin:admin`.

Envoy Gateway has examples of dashboard for you to get started:

### Envoy Proxy Global

![Envoy Proxy Global](/img/envoy-proxy-global-dashboard.png)

### Envoy Clusters

![Envoy Clusters](/img/envoy-clusters-dashboard.png)

### Envoy Pod Resources

![Envoy Pod Resources](/img/resources-monitor-dashboard.png)

You can load the above dashboards in your Grafana to get started. Please refer to Grafana docs for [importing dashboards](https://grafana.com/docs/grafana/latest/dashboards/manage-dashboards/#import-a-dashboard).
