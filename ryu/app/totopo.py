from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info


def Topology():
    net = Mininet(controller=RemoteController, switch=OVSSwitch)

    info('create controller...\n')
    c1 = net.addController('c1', ip='127.0.0.1', port=6653)
    c2 = net.addController('c2', ip='127.0.0.1', port=6654)

    info('create sitchs...\n')
    # swList = []
    # for sN in swNumber+1:
    #     swList.append(net.addSwitch('s%s'%sN+1,dpid = sN))
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    s4 = net.addSwitch('s4')
    s5 = net.addSwitch('s5')
    s6 = net.addSwitch('s6')
    s11 = net.addSwitch('s11')
    s12 = net.addSwitch('s12')
    s13 = net.addSwitch('s13')
    s14 = net.addSwitch('s14')
    s15 = net.addSwitch('s15')
    s16 = net.addSwitch('s16')
    switch_1 = [s1, s2, s3, s4, s5, s6]
    switch_2 = [s11, s12, s13, s14, s15, s16]
    for switch in switch_1:
        info('%s ' % switch.name)
    for switch in switch_2:
        info('%s ' % switch.name)

    info('\ncreate hosts...\n')
    h1 = net.addHost('h1', mac='00:00:00:00:00:01', ip='192.168.1.1/24')
    h2 = net.addHost('h2', mac='00:00:00:00:00:02', ip='192.168.1.2/24')
    h3 = net.addHost('h3', mac='00:00:00:00:00:03', ip='192.168.1.3/24')
    h4 = net.addHost('h4', mac='00:00:00:00:00:04', ip='192.168.1.4/24')
    # info('{} {} {}\n'.format(h1.name,h2.name,h3.name))
    info('{} {} {} {}\n'.format(h1.name, h2.name, h3.name, h4.name))

    info('create links...\n')

    # add switch links
    # s1 to anthor switch
    net.addLink(s1, h1, 1, 1)
    net.addLink(s1, s2, 2, 2)
    net.addLink(s1, s5, 3, 3)
    # s2 to anthor switch
    net.addLink(s2, s3, 1, 1)
    net.addLink(s2, s4, 3, 3)
    net.addLink(s2, s5, 5, 5)
    net.addLink(s2, s6, 4, 2)
    # s3 to anthor switch
    net.addLink(s3, s5, 2, 4)
    net.addLink(s3, s13, 3, 3)     #anthor area cascade link
    # s4 to anthor switch
    net.addLink(s4, h2, 1, 1)
    net.addLink(s4, s5, 2, 2)
    # s5 to anthor switch
    net.addLink(s5, s6, 1, 1)
    # s6 to anthor switch
    net.addLink(s6, s16, 3, 3)     #anthor area cascade link
    # s11 to anthor switch
    net.addLink(s11, h3, 1, 1)
    net.addLink(s11, s12, 2, 2)
    net.addLink(s11, s15, 3, 3)
    # s12 to anthor switch
    net.addLink(s12, s13, 1, 1)
    net.addLink(s12, s14, 3, 3)
    net.addLink(s12, s15, 5, 5)
    net.addLink(s12, s16, 4, 2)
    # s13 to anthor switch
    net.addLink(s13, s15, 2, 4)
    # s14 to anthor switch
    net.addLink(s14, h4, 1, 1)
    net.addLink(s14, s15, 2, 2)
    # s15 to anthor switch
    net.addLink(s15, s16, 1, 1)
    # s16 to anthor switch

    info('starting network...\n')
    net.build()
    for switch in switch_1:
        switch.start([c1])
    for switch in switch_2:
        switch.start([c2])
    # set host gateway
    # h1.cmd('ip route add default via 192.168.1.1')
    # h2.cmd('ip route add default via 192.168.2.1')
    # h3.cmd('ip route add default via 192.168.3.1')
    CLI(net)

    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    Topology()
