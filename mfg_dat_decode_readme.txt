802.1x Credential Extraction Tool
Copyright (c) 2018 devicelocksmith.com
Version: 1.04


1. Access shell on a rooted Motorola or Arris FTTH router.
2. Use the following command to extract keystore to /tmp on the router:
   mount mtd:mfg -t jffs2 /mfg&&cp /mfg/mfg.dat /tmp/&&umount /mfg
   On older routers you may need to copy the whole mfg partition to a file with:
   dd if=/dev/mtdblock4 of=/tmp/mfg.dat bs=1k
3. Copy mfg.dat from /tmp/ to your PC and place it into the same folder 
   as mfg_dat_decode.exe
4. Copy *.der files from /etc/rootcert to the folder of the
   tool.
5. Run mfg_dat_decode. You should get a tar.gz file with EAP-TLS 
   credentials in the same folder.

I could not help you with acquiring root access to your gateway.

The tool is free to use for non-commercial purposes.
Government and commercial entities, moderators and administrators of
DSLReports forum are not permitted to use this software without 
acquiring a commercial license.

By using this tool, you agree to the following:

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
