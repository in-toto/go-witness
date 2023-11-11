import ctypes
import json

class WitnessSDK:
    def __init__(self, lib_path):
        self.lib = ctypes.CDLL(lib_path)
        self.lib.RunWrapper.argtypes = [ctypes.c_char_p]
        self.lib.RunWrapper.restype = ctypes.c_char_p

    def run(self, step_name, key_path, cert_path, intermediate_paths):
        options = {
            "step_name": step_name,
            "key_path": key_path,
            "cert_path": cert_path,
            "intermediate_paths": intermediate_paths
        }
        options_json = json.dumps(options)
        result = self.lib.RunWrapper(options_json.encode('utf-8'))
        return json.loads(result.decode('utf-8'))

    def test_run(self):
        # Example test run with predefined paths
        test_step_name = "ExampleStep"
        test_key_path = "keys_and_certs/private_key.pem"
        test_cert_path = "keys_and_certs/certificate.pem"
        test_intermediate_paths = []  # Update this if you have intermediate certificates

        result = self.run(test_step_name, test_key_path, test_cert_path, test_intermediate_paths)
        print("Test Run Result:", result)

# Example usage
# sdk = WitnessSDK('./witnesslib.so')
# sdk.test_run()
