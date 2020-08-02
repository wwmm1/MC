import schedule
import time
from multiple_Controller import SimpleSwitch13


s = SimpleSwitch13()

s
time.sleep(20)
s.send_heartbeat_packet()




