"""Names shared by the network profile and sample-trace generators."""
import re


def address_family_module(family):
    if not re.fullmatch('[46]{3}', family):
        raise ValueError('Expected the Red, Gray, and Black IP families, such as 446')
    return f'DualStack_RedV{family[0]}_GrayV{family[1]}_BlackV{family[2]}'


def tunnel_matrix_module(namespace, direction):
    pairing = namespace.removeprefix('Pairing')
    pairing = re.sub(r'^(Ipsec|Macsec)(Ipsec|Macsec)', r'Inner\1_Outer\2_', pairing)
    pairing = pairing.replace('InnerMacsecOuterIpsec', 'InnerMacsec_OuterIpsec_')
    suffix = direction.replace('Forward', 'Fwd').replace('Reverse', 'Rev').replace('VLAN', '_VLAN')
    return 'TunnelMatrix_' + pairing.rstrip('_') + '_' + suffix


def forwarding_lean(source):
    """Render older trace labels using the current Lean forwarding names."""
    source = source.replace('DataPlaneForwarding.Step.local', 'DataPlaneForwarding.Step.deliverToLocalHost')
    source = source.replace('Step.«local»', 'Step.deliverToLocalHost')
    for old, new in [('ready', 'egressReady'), ('local', 'internalProcessing'),
                     ('passWithoutTransform', 'forwardWithoutEncap'), ('plain', 'forwardWithoutEncap'),
                     ('wire', 'linkTransmit'), ('switch', 'bridge')]:
        source = re.sub(r'\.' + old + r'\b', '.' + new, source)
    source = re.sub(r'\bRoute\b', 'FibRoute', source)
    source = re.sub(r'(?<=[\w)])\.inbound\b', '.ingressPolicies', source)
    source = re.sub(r'(?<=[\w)])\.outbound\b', '.egressPolicies', source)
    return re.sub(r'/\-.*?\-/', '', source, flags=re.S)
