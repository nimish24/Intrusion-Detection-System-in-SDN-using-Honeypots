 """Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        H1 = self.addHost( 'h1' )
        H2 = self.addHost( 'h2' )
        H3 = self.addHost( 'h3' )
        H4 = self.addHost( 'h4' )
        S3 = self.addSwitch( 's3' )

        # Add links
        self.addLink( H1, S3 )
        self.addLink( H2, S3 )
        self.addLink( H3, S3 )
        self.addLink( H4, S3 )


topos = { 'mytopo': ( lambda: MyTopo() ) }
