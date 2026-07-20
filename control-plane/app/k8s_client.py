from kubernetes import client, config
from kubernetes.client.rest import ApiException
import os
import logging

from .addon_detection import match_addon

logger = logging.getLogger(__name__)

class K8sClient:
    def __init__(self):
        self.authorized = False
        try:
            # Try loading in-cluster config first
            config.load_incluster_config()
            self.authorized = True
            logger.info("Loaded in-cluster Kubernetes config")
        except config.ConfigException:
            try:
                # Fallback to local kubeconfig
                config.load_kube_config()
                self.authorized = True
                logger.info("Loaded local kubeconfig")
            except config.ConfigException:
                logger.warning("Could not load Kubernetes configuration. K8s features will be disabled.")
                self.authorized = False

        if self.authorized:
            self.core_v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            self.rbac_v1 = client.RbacAuthorizationV1Api()
            self.apiextensions_v1 = client.ApiextensionsV1Api()
            self.custom_objects = client.CustomObjectsApi()
            self.version_api = client.VersionApi()

    def get_nodes(self):
        if not self.authorized: return {"error": "K8s not configured"}
        try:
            nodes = self.core_v1.list_node()
            return [{"name": n.metadata.name, "status": n.status.conditions[-1].type, "version": n.status.node_info.kubelet_version} for n in nodes.items]
        except ApiException as e:
            logger.error(f"Error fetching nodes: {e}")
            return {"error": str(e)}

    def get_namespaces(self):
        if not self.authorized: return {"error": "K8s not configured"}
        try:
            ns = self.core_v1.list_namespace()
            return [n.metadata.name for n in ns.items]
        except ApiException as e:
            return {"error": str(e)}

    def get_pods(self, namespace="default"):
        if not self.authorized: return {"error": "K8s not configured"}
        try:
            pods = self.core_v1.list_namespaced_pod(namespace)
            return [{"name": p.metadata.name, "status": p.status.phase, "ip": p.status.pod_ip} for p in pods.items]
        except ApiException as e:
            return {"error": str(e)}

    def get_logs(self, namespace, pod_name, tail_lines=100):
        if not self.authorized: return "K8s not configured"
        try:
            return self.core_v1.read_namespaced_pod_log(pod_name, namespace, tail_lines=tail_lines)
        except ApiException as e:
            return f"Error reading logs: {e}"

    def detect_addons(self) -> list:
        """
        Scan all Deployments and DaemonSets cluster-wide to detect running
        add-ons and their versions by matching container images. Mirrors
        RemoteK8sClient.detect_addons() in cve_service.py but uses the
        in-cluster Kubernetes Python client instead of raw HTTP calls.

        Returns a list of dicts: {name, version, namespace, workload, image}
        """
        if not self.authorized:
            return []

        addons: list = []
        seen: set = set()  # (addon_name, version) dedup

        try:
            workloads = (
                self.apps_v1.list_deployment_for_all_namespaces().items
                + self.apps_v1.list_daemon_set_for_all_namespaces().items
            )
        except ApiException as e:
            logger.warning(f"Failed to list deployments/daemonsets for addon detection: {e}")
            return []

        for item in workloads:
            ns = item.metadata.namespace
            workload_name = item.metadata.name
            spec = item.spec.template.spec
            containers = (spec.containers or []) + (spec.init_containers or [])

            for container in containers:
                image = container.image or ""
                match = match_addon(image)
                if not match:
                    continue
                addon_name, version = match
                key = (addon_name, version)
                if key not in seen:
                    seen.add(key)
                    addons.append({
                        "name": addon_name,
                        "version": version,
                        "namespace": ns,
                        "workload": workload_name,
                        "image": image,
                    })
        return addons

    def get_crds(self):
        if not self.authorized: return {"error": "K8s not configured"}
        try:
            crds = self.apiextensions_v1.list_custom_resource_definition()
            return [{"name": crd.metadata.name, "scope": crd.spec.scope} for crd in crds.items]
        except ApiException as e:
            return {"error": str(e)}

    def list_jit_requests(self, namespace="default"):
        if not self.authorized: return []
        try:
            # Group: provenance.io, Version: v1alpha1, Plural: jitaccessrequests
            return self.custom_objects.list_namespaced_custom_object(
                "provenance.io", "v1alpha1", namespace, "jitaccessrequests"
            )
        except ApiException as e:
            logger.error(f"Error listing JIT requests: {e}")
            return []

    def create_jit_request(self, namespace, requestor, role_ref, duration, reason):
        if not self.authorized: raise Exception("K8s not configured")
        
        body = {
            "apiVersion": "provenance.io/v1alpha1",
            "kind": "JITAccessRequest",
            "metadata": {
                "generateName": "jit-req-",
                "namespace": namespace
            },
            "spec": {
                "requestor": requestor,
                "namespace": namespace, # Target namespace
                "roleRef": role_ref,
                "duration": duration,
                "reason": reason
            }
        }
        
        return self.custom_objects.create_namespaced_custom_object(
            "provenance.io", "v1alpha1", namespace, "jitaccessrequests", body
        )

    def get_rbac_graph_data(self):
        """
        Fetches all Roles, ClusterRoles, RoleBindings, and ClusterRoleBindings
        to construct a graph.
        """
        if not self.authorized: return {"error": "K8s not configured"}
        
        try:
            roles = self.rbac_v1.list_role_for_all_namespaces().items
            cluster_roles = self.rbac_v1.list_cluster_role().items
            role_bindings = self.rbac_v1.list_role_binding_for_all_namespaces().items
            cluster_role_bindings = self.rbac_v1.list_cluster_role_binding().items

            # Token-automount rule inputs (CIS 5.1.6). Fetched separately so a
            # scanner whose RBAC role lacks pods/serviceaccounts list permission
            # still gets the binding-based rules instead of a failed scan.
            service_accounts, pods = [], []
            try:
                service_accounts = [{
                    "name": s.metadata.name, "namespace": s.metadata.namespace,
                    "kind": "ServiceAccount",
                    "automountServiceAccountToken": s.automount_service_account_token,
                } for s in self.core_v1.list_service_account_for_all_namespaces().items]
                pods = [{
                    "name": p.metadata.name, "namespace": p.metadata.namespace, "kind": "Pod",
                    "service_account_name": p.spec.service_account_name,
                    "automountServiceAccountToken": p.spec.automount_service_account_token,
                } for p in self.core_v1.list_pod_for_all_namespaces().items]
            except ApiException as e:
                logger.warning(f"token-automount inputs unavailable (serviceaccounts/pods list): {e}")

            
            def _rules(rules):
                return [{
                    "verbs": rule.verbs or [],
                    "resources": rule.resources or [],
                    "api_groups": rule.api_groups or [],
                    "resource_names": rule.resource_names or [],
                } for rule in (rules or [])]

            return {
                "roles": [{
                    "name": r.metadata.name, "namespace": r.metadata.namespace, "kind": "Role",
                    "rules": _rules(r.rules),
                } for r in roles],
                "cluster_roles": [{
                    "name": r.metadata.name, "kind": "ClusterRole",
                    "rules": _rules(r.rules),
                } for r in cluster_roles],
                "role_bindings": [{
                    "name": rb.metadata.name,
                    "namespace": rb.metadata.namespace,
                    "kind": "RoleBinding",
                    "roleRef": rb.role_ref.to_dict(),
                    "subjects": [s.to_dict() for s in (rb.subjects or [])]
                } for rb in role_bindings],
                "cluster_role_bindings": [{
                    "name": crb.metadata.name,
                    "kind": "ClusterRoleBinding",
                    "roleRef": crb.role_ref.to_dict(),
                    "subjects": [s.to_dict() for s in (crb.subjects or [])]
                } for crb in cluster_role_bindings],
                "service_accounts": service_accounts,
                "pods": pods
            }
        except ApiException as e:
            logger.error(f"Error fetching RBAC data: {e}")
            return {"error": str(e)}

# Singleton instance
k8s_client = K8sClient()
