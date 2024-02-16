# BitTrace-Kernel
The kernel modules to trace the system internal events.

----------------------------------------------------------------------------------------------------------------------------------------------------------------
For the source code license, please refer to the LICENSE file.
Please Note: For commercial use you need to inquiry the commercial license, please refer to the detail in the LICENSE file.
----------------------------------------------------------------------------------------------------------------------------------------------------------------

Bittrace is publish on software site huajun(chinese version), download.cnet(english version) and other software download site:
 
  http://www.onlinedown.net/soft/256910.htm
  ![ui](https://github.com/codereba/bittrace/blob/master/images/download.png)
 
  https://download.cnet.com/Bittrace/3000-2094_4-76472582.html?part=dl-&subj=dl&tag=button
 
  ![ui](https://github.com/codereba/bittrace/blob/master/images/ui.jpg)
  video lesson:
 
  http://v.youku.com/v_show/id_XMTQwMDU0NTYzNg==.html?from=y1.7-1.2

  Kernel drivers include:
  file system mini filter driver
  ndis intermediate driver
  ndis filter driver
  tdi driver
  wfp driver
  kernel hook driver
  io port filter driver(usb port)
  disk filter driver 
  registry filter driver
  high perfermonce log driver

Please Note:
The the kernel module for receiving the events of the system from many other kernel modules(like the registry, file system, network, usb port etc.) and reporting the events to bittrace application. is open source, for other kernel module, please request the license from the author by the email: gangootech@hotmail.com.

Prerequisites:
  1. Visual Studio 2008 (or 2010,2015)
  2. Windows driver development kit (WDK).

The build steps:
  1. Open the command line of WDK.
  2. Use the build command to build this driver.

Contact:
  Email: shi.jijie@gmail.com
  WeiXin: 651362705
  QQ group: 601169305
  QQ: 2146651351

Donation:
  Alipay: shi.jijie@hotmail.com
