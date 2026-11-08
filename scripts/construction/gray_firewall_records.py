"""Normalize the separate repaired Gray firewall phase without changing earlier captures."""
from pathlib import Path
from boundary_records import build


def main():
    build(Path('outputs/mcp/exported/v31r-shared-gray-replies-multi_protocol_execution.json'),
          Path('outputs/mcp/exported/v31r-red-services-red_service_policy.json'),
          Path('data/evidence/continuation/GrayFirewallShared.json'),
          Path('outputs/mcp/exported/v31r-underlay-policy-underlay_control_policy.json'))


if __name__ == '__main__':
    main()
