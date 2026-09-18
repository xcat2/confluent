import asyncssh
import confluent.sshclient as sshclient
import confluent.discovery.handlers.generic as generic
import confluent.netutil as netutil

class NodeHandler(generic.NodeHandler):
    devname = 'NVOS Switch'

    def get_firmware_default_account_info(self):
        return ('admin', 'admin')

    async def config(self, nodename):
        ncreds = self.configmanager.get_node_attributes(nodename, ['secret.adminuser', 'secret.adminpassword'], decrypt=True)
        ncreds = ncreds.get(nodename, {})
        adminuser = ncreds.get('secret.adminuser', {}).get('value', 'admin')
        if isinstance(adminuser, bytes):
            adminuser = adminuser.decode('utf-8')
        if adminuser != 'admin':
            raise ValueError("nvos support does not support renaming the admin user")
        adminpass = ncreds.get('secret.adminpassword', {}).get('value')
        if isinstance(adminpass, bytes):
            adminpass = adminpass.decode('utf-8')
        if not adminpass:
            raise ValueError("secret.adminpassword must be specified for " + nodename)
        myaddress = self.info.get('addresses', [[None]])[0][0]
        if not myaddress:
            raise ValueError("No address found for request")
        hwaddr = self.info.get('hwaddr')
        myaddress = self.info.get('addresses', [[None]])[0][0]
        if myaddress:
            attrset = {'deployment.client_ip': myaddress}
            if hwaddr:
                myip = await netutil.my_ip_facing(myaddress)
                if myip:
                    niccfg = await netutil.get_nic_config(self.configmanager, nodename, serverip=myip)
                    cfgname = niccfg.get('config_name', None)
                    if cfgname:
                        attrname = f'net.{cfgname}.hwaddr'
                    else:
                        attrname = 'net.hwaddr'
                    attrset[attrname] = hwaddr
            await self.configmanager.set_node_attributes({nodename: attrset})
            try:
                async with sshclient.connect(myaddress, username=adminuser, password=adminpass, nodename=nodename, configmanager=self.configmanager) as conn:
                    pass
            except asyncssh.misc.PermissionDenied:  # try admin, admin
                async with sshclient.connect(myaddress, username='admin', password='admin', nodename=nodename, configmanager=self.configmanager) as conn:
                    res = await conn.run(f"nv set system aaa user admin password '{adminpass}'")
                    if res.exit_status == 0:
                        res = await conn.run('nv config apply')
                    if res.exit_status != 0:
                        raise RuntimeError("Failed to apply NVOS configuration")
                    