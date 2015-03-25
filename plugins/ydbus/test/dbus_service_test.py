#!/usr/bin/python

# dbus_service_test.py
#  Testing for D-Bus dissection
#  Copyright 2015, Lucas Hong Tran <hongtd2k@gmail.com>
# 
#  Protocol specification available at http://dbus.freedesktop.org/doc/dbus-specification.html
# 
# 
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


import gobject
import sys

import dbus
import dbus.service
import time
import pprint

BUS='com.ydbus.sigtest'
PATH='/com/ydbus/sigtest'
IFACE='com.ydbus.sigtest'

START_TIME=time.time ()

class DbusSigTest(dbus.service.Object):
    def __init__ (self):
        
        self.bus = dbus.SystemBus ()
        bus_name = dbus.service.BusName (BUS, bus=self.bus)
        dbus.service.Object.__init__ (self, bus_name, PATH)
    
    def sig_print(self, func_name, **kwargs):
         print "====> Function '{func_name}' =============" .format( func_name = func_name )
         for k, v in kwargs.iteritems():            
            print "param '{k}', {type}" .format( k=k, type=type(k) )  
            pprint.pprint (v)
         print '======================================='

    @dbus.service.method(dbus_interface=IFACE,
                         in_signature='s',
                         out_signature='s')
    def sig_test_err1(self, p0):
        func_name = sys._getframe().f_code.co_name
        self.sig_print(func_name, p0=p0)
        return p0; 
 

    @dbus.service.method(dbus_interface=IFACE,
                         in_signature='ss',
                         out_signature='s')
    def sig_test_err2(self, p0, p1):
        func_name = sys._getframe().f_code.co_name
        self.sig_print(func_name, p0=p0, p1=p1)
        return p0; 
   

    @dbus.service.method(dbus_interface=IFACE,
                         in_signature='sss',
                         out_signature='s')
    def sig_test_err3(self, p0, p1, p2):
        func_name = sys._getframe().f_code.co_name
        self.sig_print(func_name, p0=p0, p1=p1, p2=p2)
        return p0; 

    @dbus.service.method(dbus_interface=IFACE,
                         in_signature='ssss',
                         out_signature='s')
    def sig_test_err4(self, p0, p1, p2, p3):
        func_name = sys._getframe().f_code.co_name
        self.sig_print(func_name, p0=p0, p1=p1, p2=p2, p3=p3)
        return p0; 


    @dbus.service.method(dbus_interface=IFACE,
                         in_signature='ai',
                         out_signature='ai')
    def sig_ai(self, p0):
        func_name = sys._getframe().f_code.co_name
        self.sig_print(func_name, p0=p0)
        return p0; 
    

from dbus.glib import DBusGMainLoop
print "Dbus service created, bus:{0}, path:{1}, iface:{2}".format(BUS, PATH, IFACE)
DBusGMainLoop (set_as_default=True)
loop = gobject.MainLoop ()
# Start the D-Bus service
sigtest = DbusSigTest ()
loop.run ()
