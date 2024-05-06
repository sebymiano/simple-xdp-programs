"""This is a Cloudlab profile to run the test for XDP.

Instructions:
Wait for the profile instance to start, it will then install the mellanox OFED packages and the DPDK packages on the pktgen, while the necessary XDP tools are installed on the DUT.
"""

# Import the Portal object.
import geni.portal as portal
# Import the ProtoGENI library.
import geni.rspec.pg as pg

# Create a portal context.
pc = portal.Context()

# Create a Request object to start building the RSpec.
request = pc.makeRequestRSpec()
 
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

pc.defineParameter("ofedAPT",  "Install OFED via APT", portal.ParameterType.BOOLEAN, False,
                    advanced=True,
                    longDescription="By default, we run the OFED installer script. If you want to use the APT package, check this box.")

# Retrieve the values the user specifies during instantiation.
params = pc.bindParameters()

# Request that a specific image be installed on this node
pktgen.disk_image = "urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD"
dut.disk_image = "urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD"

pktgen.hardware_type = params.phystype
dut.hardware_type = params.phystype

# Create a link between the two nodes
link1 = request.Link(members = [pktgen, dut], linkSpeed=params.linkSpeed)
link2 = request.Link(members = [pktgen, dut], linkSpeed=params.linkSpeed)

if params.ofedAPT:
    pktgen.addService(pg.Execute(shell="bash", command='/local/repository/profiles/setup-pktgen.sh -a'))
else:
    pktgen.addService(pg.Execute(shell="bash", command='/local/repository/profiles/setup-pktgen.sh'))

dut.addService(pg.Execute(shell="sh", command="/local/repository/upgrade-kernel.sh -q"))

portal.context.printRequestRSpec()