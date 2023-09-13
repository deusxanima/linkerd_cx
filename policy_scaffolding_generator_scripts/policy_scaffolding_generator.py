import json
import yaml
import hashlib

class ResourceGenerator:
    def __init__(self, templates):
        self.templates = templates
        self.generated_servers = set()
        self.generated_routes = set()
        self.generated_mesh_tls_auth = set()
        self.generated_auth_policies = set()
        self.server_name = ""
        self.http_route_name = ""
        self.auth_policy_map = {}  # Dictionary to map Auth Policies to HTTPRoutes

    def generate_server(self, destination_namespace, destination_pod, destination_port):
        self.server_name = f"{destination_pod}-server-{destination_port}"
        if self.server_name not in self.generated_servers:
            server_resource = self.templates["server_template"].format(
                namespace=destination_namespace,
                server_name=self.server_name,
                destination_pod=destination_pod,
                destination_port=destination_port,
            )
            self.generated_servers.add(self.server_name)
            return server_resource
        return ""

    def generate_http_route(self, destination_namespace, destination_pod, path, method):
        unique_identifier = hashlib.md5(f"{destination_pod}-{path}-{method}".encode()).hexdigest()
        self.http_route_name = f"{self.server_name}-http-route-{unique_identifier}"

        if self.http_route_name not in self.generated_routes:
            http_route_resource = self.templates["http_route_template"].format(
                namespace=destination_namespace,
                http_route_name=self.http_route_name,
                server_name=self.server_name,
                path=path,
                method=method,
            )
            self.generated_routes.add(self.http_route_name)
            return http_route_resource
        return ""

    def generate_mesh_tls(self, destination_namespace, client_identity):
        mesh_tls_name = f"{client_identity}-mesh-tls"
        if mesh_tls_name not in self.generated_mesh_tls_auth:
            mesh_tls_resource = self.templates["mesh_tls_template"].format(
                namespace=destination_namespace,
                mesh_tls_name=mesh_tls_name,
                client_identity=client_identity,
            )
            self.generated_mesh_tls_auth.add(mesh_tls_name)
            return mesh_tls_resource
        return ""

    def generate_auth_policy(self, destination_namespace, http_route_name, mesh_tls_name):
        auth_policy_name = f"{self.http_route_name}-auth-policy"
        if auth_policy_name not in self.generated_auth_policies:
            auth_policy_resource = self.templates["auth_policy_template"].format(
                namespace=destination_namespace,
                auth_policy_name=auth_policy_name,
                http_route_name=self.http_route_name,
                mesh_tls_name=mesh_tls_name,
            )
            self.generated_auth_policies.add(auth_policy_name)

            # Map the Auth Policy to the associated HTTPRoute
            self.auth_policy_map[auth_policy_name] = self.http_route_name
            return auth_policy_resource
        return ""

    def validate_http_routes(self):
        for route_name in self.generated_routes:
            if route_name not in self.generated_auth_policies:
                print(f"Warning: HTTPRoute {route_name} is not referenced by any auth policy.")

    def get_http_route_for_auth_policy(self, auth_policy_name):
        return self.auth_policy_map.get(auth_policy_name, None)

def load_templates(template_file):
    with open(template_file, "r") as file:
        templates = yaml.load(file, Loader=yaml.FullLoader)
    return templates

def main():
    tap_data_file = "tap_data.json"
    output_file = "output.yaml"
    template_file = "templates.yaml"

    templates = load_templates(template_file)
    resource_generator = ResourceGenerator(templates)

    with open(tap_data_file, "r") as file:
        tap_data_json = file.read()

    tap_data = json.loads(tap_data_json)

    with open(output_file, "w") as output:
        for entry in tap_data:
            source_namespace = entry["source"]["metadata"]["namespace"]
            source_pod = entry["source"]["metadata"]["pod"]

            destination_namespace = entry["destination"]["metadata"]["namespace"]
            destination_pod = entry["destination"]["metadata"]["pod"]
            destination_port = entry["destination"]["port"]

            client_identity = entry["source"]["metadata"].get("client_id", "default_value")

            if "requestInitEvent" in entry:
                request_init_event = entry["requestInitEvent"]
                path = request_init_event.get("path", "/")
                method = request_init_event.get("method", "GET")
                
                if entry.get("proxyDirection") != "OUTBOUND":
                    server_resource = resource_generator.generate_server(destination_namespace, destination_pod, destination_port)
                    http_route_resource = resource_generator.generate_http_route(destination_namespace, destination_pod, path, method)
                    mesh_tls_resource = resource_generator.generate_mesh_tls(destination_namespace, client_identity)

                    http_route_name = f"{destination_pod}-{path.replace('/', '-')}-http-route"
                    mesh_tls_name = f"{client_identity}-mesh-tls"

                    auth_policy_resource = resource_generator.generate_auth_policy(destination_namespace, http_route_name, mesh_tls_name)

                    resources = [server_resource, http_route_resource, mesh_tls_resource, auth_policy_resource]
                    resources = [res for res in resources if res]  # Remove empty strings

                    for resource in resources:
                        output.write(resource)
                        output.write("\n---\n")

if __name__ == "__main__":
    main()