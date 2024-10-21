"""This is a Cloudlab profile to run the test for XDP.

Instructions:
Wait for the profile instance to start, it will then install the mellanox OFED packages and the DPDK packages on the pktgen, while the necessary XDP tools are installed on the DUT.
"""

# Import the Portal object.
import geni.portal as portal
# Import the ProtoGENI library.
import geni.rspec.pg as pg
# Import the Emulab specific extensions.
import geni.rspec.emulab as emulab

# Create a portal context.
pc = portal.Context()

# Create a Request object to start building the RSpec.
request = pc.makeRequestRSpec()

# Do not run snmpit
#request.skipVlans()

# Add a raw PC to the request.
pktgen = request.RawPC("pktgen")
dut = request.RawPC("dut")

# Optional physical type for nodes.
pc.defineParameter("phystype",  "Optional physical node type",
                   portal.ParameterType.STRING, "sm110p",
                   longDescription="Specify a physical node type (c220g1,xl170,etc).")

pc.defineParameter("phystype", "Switch type",
                   portal.ParameterType.STRING, "dell-s4048",
                   [('mlnx-sn2410', 'Mellanox SN2410'),
                    ('dell-s4048',  'Dell S4048')])

# Optional link speed, normally the resource mapper will choose for you based on node availability
pc.defineParameter("linkSpeed", "Link Speed", portal.ParameterType.INTEGER, 100000000,
                   [(0,"Any"),(100000,"100Mb/s"),(1000000,"1Gb/s"),(10000000,"10Gb/s"),(25000000,"25Gb/s"),(100000000,"100Gb/s")],
                   advanced=True,
                   longDescription="A specific link speed to use for your lan. Normally the resource " +
                   "mapper will choose for you based on node availability and the optional physical type.")
                
                
# Retrieve the values the user specifies during instantiation.
params = pc.bindParameters()

# Request that a specific image be installed on this node
pktgen.disk_image = "urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD"
dut.disk_image = "urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD"

pktgen.hardware_type = params.phystype
dut.hardware_type = params.phystype

# Add Switch to the request and give it a couple of interfaces
mysw = request.Switch("mysw")
mysw.hardware_type = params.phystype
swiface_n1if1 = mysw.addInterface()
swiface_n2if1 = mysw.addInterface()
swiface_n1if2 = mysw.addInterface()
swiface_n2if2 = mysw.addInterface()

# Add interfaces to the nodes.
iface1_node1 = pktgen.addInterface("n1if1")
iface2_node1 = pktgen.addInterface("n1if2")

iface1_node2 = dut.addInterface("n2if1")
iface2_node2 = dut.addInterface("n2if2")

link1 = request.L1Link("link_n1if1")
link1.addInterface(iface1_node1)
link1.addInterface(swiface_n1if1)

link2 = request.L1Link("link_n1if2")
link2.addInterface(iface2_node1)
link2.addInterface(swiface_n1if2)

link3 = request.L1Link("link_n2if1")
link3.addInterface(iface1_node2)
link3.addInterface(swiface_n2if1)

link4 = request.L1Link("link_n2if2")
link4.addInterface(iface2_node2)
link4.addInterface(swiface_n2if2)

# Print the RSpec to the enclosing page.
pc.printRequestRSpec(request)

# Create a link between the two nodes
# link1 = request.Link(members = [pktgen, dut])
# link2 = request.Link(members = [pktgen, dut])

# pktgen_cmd = 'sudo /local/repository/profiles/setup-pktgen.sh'
# dut_cmd = 'sudo /local/repository/profiles/setup-dut.sh'
# if params.ofedAPT:
#     pktgen_cmd += ' -a'
#     dut_cmd += ' -a'

# if params.llvmVersion:
#     dut_cmd += ' -l ' + params.llvmVersion

# pktgen.addService(pg.Execute(shell="bash", command=pktgen_cmd))
# dut.addService(pg.Execute(shell="bash", command=dut_cmd))

# portal.context.printRequestRSpec()