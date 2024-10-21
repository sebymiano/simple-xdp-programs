"""This profile allocates two bare metal nodes and connects them directly together via a layer1 link. 

Instructions:
Click on any node in the topology and choose the `shell` menu item. When your shell window appears, use `ping` to test the link."""

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
                   portal.ParameterType.STRING, "r650",
                   longDescription="Specify a physical node type (c220g1,xl170,etc).")

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

# Add interfaces to the nodes.
iface1_node1 = pktgen.addInterface("n1if1")
iface2_node1 = pktgen.addInterface("n1if2")

iface1_node2 = dut.addInterface("n2if1")
iface2_node2 = dut.addInterface("n2if2")

# Add two L1 links (back-to-back connections) between node1 and node2.
link1 = request.L1Link("link1")
link1.addInterface(iface1_node1)
link1.addInterface(iface1_node2)

link2 = request.L1Link("link2")
link2.addInterface(iface2_node1)
link2.addInterface(iface2_node2)

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