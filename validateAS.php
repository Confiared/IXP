<?php
//load data
if(!file_exists('data.json'))
    die('No AS in progress');
$data=json_decode(file_get_contents('data.json'),true);
if($data===null)
    die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);

//defense in depth: data.json values below are interpolated into shell commands and BGP config
function h($s){return htmlspecialchars((string)$s,ENT_QUOTES,'UTF-8');}
if(isset($data['peer4'])&&filter_var($data['peer4'],FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)===false)
    die('peer4 invalido');
if(isset($data['peer6'])&&filter_var($data['peer6'],FILTER_VALIDATE_IP,FILTER_FLAG_IPV6)===false)
    die('peer6 invalido');
$data['asn']=(int)$data['asn'];
$data['name']=preg_replace('#[^A-Za-z0-9 ._-]#','',isset($data['name'])?$data['name']:'');
foreach(array('ipv4rangelist'=>FILTER_FLAG_IPV4,'ipv6rangelist'=>FILTER_FLAG_IPV6,'ipv4list'=>FILTER_FLAG_IPV4,'ipv6list'=>FILTER_FLAG_IPV6) as $k=>$flag)
{
    if(!isset($data[$k])||!is_array($data[$k])) continue;
    foreach($data[$k] as $v)
    {
        $ip=preg_replace('#[^0-9A-Fa-f:.].*$#','',preg_replace('#/.*$#','',$v));
        if(filter_var($ip,FILTER_VALIDATE_IP,$flag)===false)
            die('entrada invalida en '.h($k));
    }
}

//No vemos su bloque 186.195.247.0 en nuestro entourno de preuva 2803:1920::e:102 verificar sur lista de bloque publicado verificar BGP is up or active via birdc s p
error_reporting(E_ALL);
ini_set('display_errors', 1);
$listFakeAS=['2803:1920::e:102'=>['IPv4'=>'192.0.2.1','IPv6'=>'3fff::1'],'2803:1920::e:103'=>['IPv4'=>'198.51.100.1','IPv6'=>'3fff:1::1'],'2803:1920::e:104'=>['IPv4'=>'203.0.113.1','IPv6'=>'3fff:2::1']];
$listsrvBGP4=['2803:1920::e:100','2803:1920::e:105'];
$listsrvBGP6=['2803:1920::e:101','2803:1920::e:106'];
$listsrvBGP=array_merge($listsrvBGP4,$listsrvBGP6);
$listvm=array_merge($listsrvBGP4,$listsrvBGP6,array_keys($listFakeAS));
//precheck
foreach($listsrvBGP as $BGPIP)
{
    $output=array();
    exec('ssh root@'.$BGPIP.' \'cp /etc/bird/bird.conf.template /etc/bird/bird.conf\'',$output,$returnvar);
    if($returnvar!=0)
        die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__.' y servidor '.$BGPIP);
}
sleep(1);
foreach($listsrvBGP as $BGPIP)
{
    $output=array();
    exec('ssh root@'.$BGPIP.' \'systemctl restart bird\'',$output,$returnvar);
    if($returnvar!=0)
        die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__.' en '.$BGPIP);
}
$index=0;
while($index<60)
{
    $isError=false;
    foreach($listsrvBGP as $BGPIP)
    {
        $output=array();
        exec('ssh root@'.$BGPIP.' \'birdc s p\' | grep -F -v \'up\' | grep -F -v \'Active\' | grep -F -v \'BIRD \' | grep -F -v \'Name       Proto      Table      State  Since         Info\'',$output,$returnvar);
        if($returnvar!=0 && $returnvar!=1)
            $isError=true;
        elseif(implode('',$output)!='')
            $isError=true;
    }
    $index++;
    if($isError)
    {
        if($index>=60)
        {
            foreach($listsrvBGP as $BGPIP)
            {
                $output=array();
                exec('ssh root@'.$BGPIP.' \'birdc s p\' | grep -F -v \'up\' | grep -F -v \'Active\' | grep -F -v \'BIRD \' | grep -F -v \'Name       Proto      Table      State  Since         Info\'',$output,$returnvar);
                if($returnvar!=0 && $returnvar!=1)
                    die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__.' y servidor '.$BGPIP.' error '.$returnvar.'<pre>'.h(implode("\n",$output)));
                elseif(implode('',$output)!='')
                    die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__.' y servidor '.$BGPIP.'<pre>'.h(implode("\n",$output)));
            }
        }
        else
            sleep(1);
    }
}

//start Sandbox
foreach($listvm as $vmIPv6)
{
    $output=array();
    exec('ssh root@'.$vmIPv6.' \'systemctl stop tcpdump\'',$output,$returnvar);
    if($returnvar!=0)
        die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__.' y servidor '.$vmIPv6);
}
foreach($listvm as $vmIPv6)
{
    $output=array();
    exec('ssh root@'.$vmIPv6.' \'echo "" > /var/log/tcpdump.log\'',$output,$returnvar);
    if($returnvar!=0)
        die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__.' y servidor '.$vmIPv6);
}
foreach($listvm as $vmIPv6)
{
    $output=array();
    exec('ssh root@'.$vmIPv6.' \'systemctl start tcpdump\'',$output,$returnvar);
    if($returnvar!=0)
        die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__.' y servidor '.$vmIPv6);
}
/*
{
  "name":"La Otra Red LPEA",
  "asn":199343,
  "ipv4rangelist":[],
  "ipv6rangelist":[
    "2a0a:6040:9800::\/48"
  ],
  "ipv4list":[],
  "ipv6list":[],
  "peer4":"172.23.255.0",
  "peer6":"2803:1920:0:1::fff0"
}
*/
if(isset($data['peer4']))
foreach($listsrvBGP4 as $BGPIPv4)
{
    //generate bird test AS
    $addtext='### AS'.$data['asn'].' - '.$data['name'].'

ipv4 table t_0099_as'.$data['asn'].';



filter f_import_as'.$data['asn'].'
prefix set allnet;
ip set allips;
int set allas;
{


    # Filter small prefixes
    if ( net ~ [ 0.0.0.0/0{25,32} ] ) then {
        bgp_large_community.add( IXP_LC_FILTERED_PREFIX_LEN_TOO_LONG );
        accept;
    }



    # Belt and braces: must have at least one ASN in the path
    if( bgp_path.len < 1 ) then {
        bgp_large_community.add( IXP_LC_FILTERED_AS_PATH_TOO_SHORT );
        accept;
    }

    # Peer ASN == route s first ASN?
    if (bgp_path.first != '.$data['asn'].' ) then {
        bgp_large_community.add( IXP_LC_FILTERED_FIRST_AS_NOT_PEER_AS );
        accept;
    }

    # set of all IPs this ASN uses to peer with on this VLAN
    allips = [ '.$data['peer4'].' ];

    # Prevent BGP NEXT_HOP Hijacking
    if !( from = bgp_next_hop ) then {

        # need to differentiate between same ASN next hop or actual next hop hijacking
        if( bgp_next_hop ~ allips ) then {
            bgp_large_community.add( IXP_LC_INFO_SAME_AS_NEXT_HOP );
        } else {
            # looks like hijacking (intentional or not)
            bgp_large_community.add( IXP_LC_FILTERED_NEXT_HOP_NOT_PEER_IP );
            accept;
        }
    }


    # Filter Known Transit Networks
    if filter_has_transit_path() then accept;

    # Belt and braces: no one needs an ASN path with > 64 hops, that s just broken
    if( bgp_path.len > 64 ) then {
        bgp_large_community.add( IXP_LC_FILTERED_AS_PATH_TOO_LONG );
        accept;
    }



    allas = [ '.$data['asn'].' ];


    # Ensure origin ASN is in the neighbors AS-SET
    if !(bgp_path.last_nonaggregated ~ allas) then {
        bgp_large_community.add( IXP_LC_FILTERED_IRRDB_ORIGIN_AS_FILTERED );
        accept;
    }

    # RPKI test - if it s INVALID or VALID, we are done
    if filter_rpki() then accept;




    accept;
}


# The route server export filter exists as the export gateway on the BGP protocol.
#
# Remember that standard IXP community filtering has already happened on the
# master -> bgp protocol pipe.

filter f_export_as'.$data['asn'].'{

    # we should strip our own communities which we used for the looking glass and filtering
    bgp_large_community.delete( [( routeserverasn, *, * )] );
    bgp_community.delete( [( routeserverasn, * )] );



    # default position is to accept:
    accept;

}







protocol pipe pp_0099_as'.$data['asn'].' {
        description "Pipe for AS'.$data['asn'].' - '.$data['name'].'";
        table master4;
        peer table t_0099_as'.$data['asn'].';
        import filter f_export_to_master;
        export where ixp_community_filter('.$data['asn'].');
}

protocol bgp pb_0099_as'.$data['asn'].' from tb_rsclient {
        description "AS'.$data['asn'].' - '.$data['name'].'";
        neighbor '.$data['peer4'].' as '.$data['asn'].';
        ipv4 {
            import limit 10 action restart;
            import filter f_import_as'.$data['asn'].';
            table t_0099_as'.$data['asn'].';
            export filter f_export_as'.$data['asn'].';
        };

}
';

    file_put_contents('temp',$addtext);
    $output=array();
    exec('rsync temp root@['.$BGPIPv4.']:/etc/bird/temp',$output,$returnvar);
    if($returnvar!=0)
        die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__.' y servidor '.$BGPIPv4);
    $output=array();
    exec('ssh root@'.$BGPIPv4.' \'cp /etc/bird/bird.conf.template /etc/bird/bird.conf\'',$output,$returnvar);
    if($returnvar!=0)
        die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__.' y servidor '.$BGPIPv4);
    $output=array();
    exec('ssh root@'.$BGPIPv4.' \'cat /etc/bird/temp >> /etc/bird/bird.conf\'',$output,$returnvar);
    if($returnvar!=0)
        die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__.' y servidor '.$BGPIPv4);
    $output=array();
    exec('ssh root@'.$BGPIPv4.' \'systemctl restart bird\'',$output,$returnvar);//only take new AS if restart. not work with reload
    if($returnvar!=0)
        die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__.' y servidor '.$BGPIPv4);
    exec('ssh root@'.$BGPIPv4.' \'echo "" > /var/log/bird/bgp*-ipv*.log\'',$output,$returnvar);//only take new AS if restart. not work with reload
    if($returnvar!=0)
        die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);
}
if(isset($data['peer6']))
foreach($listsrvBGP6 as $BGPIPv6)
{
    //generate bird test AS
    $addtext='### AS'.$data['asn'].' - '.$data['name'].'

ipv6 table t_0099_as'.$data['asn'].';



filter f_import_as'.$data['asn'].'
prefix set allnet;
ip set allips;
int set allas;
{


    # Filter small prefixes
    if ( net ~ [ ::/0{49,128} ] ) then {
        bgp_large_community.add( IXP_LC_FILTERED_PREFIX_LEN_TOO_LONG );
        accept;
    }



    # Belt and braces: must have at least one ASN in the path
    if( bgp_path.len < 1 ) then {
        bgp_large_community.add( IXP_LC_FILTERED_AS_PATH_TOO_SHORT );
        accept;
    }

    # Peer ASN == route s first ASN?
    if (bgp_path.first != '.$data['asn'].' ) then {
        bgp_large_community.add( IXP_LC_FILTERED_FIRST_AS_NOT_PEER_AS );
        accept;
    }

    # set of all IPs this ASN uses to peer with on this VLAN
    allips = [ '.$data['peer6'].' ];

    # Prevent BGP NEXT_HOP Hijacking
    if !( from = bgp_next_hop ) then {

        # need to differentiate between same ASN next hop or actual next hop hijacking
        if( bgp_next_hop ~ allips ) then {
            bgp_large_community.add( IXP_LC_INFO_SAME_AS_NEXT_HOP );
        } else {
            # looks like hijacking (intentional or not)
            bgp_large_community.add( IXP_LC_FILTERED_NEXT_HOP_NOT_PEER_IP );
            accept;
        }
    }


    # Filter Known Transit Networks
    if filter_has_transit_path() then accept;

    # Belt and braces: no one needs an ASN path with > 64 hops, that s just broken
    if( bgp_path.len > 64 ) then {
        bgp_large_community.add( IXP_LC_FILTERED_AS_PATH_TOO_LONG );
        accept;
    }



    allas = [ '.$data['asn'].' ];


    # Ensure origin ASN is in the neighbors AS-SET
    if !(bgp_path.last_nonaggregated ~ allas) then {
        bgp_large_community.add( IXP_LC_FILTERED_IRRDB_ORIGIN_AS_FILTERED );
        accept;
    }

    # RPKI test - if it s INVALID or VALID, we are done
    if filter_rpki() then accept;


    accept;
}


# The route server export filter exists as the export gateway on the BGP protocol.
#
# Remember that standard IXP community filtering has already happened on the
# master -> bgp protocol pipe.

filter f_export_as'.$data['asn'].'{

    # we should strip our own communities which we used for the looking glass and filtering
    bgp_large_community.delete( [( routeserverasn, *, * )] );
    bgp_community.delete( [( routeserverasn, * )] );



    # default position is to accept:
    accept;

}







protocol pipe pp_0099_as'.$data['asn'].' {
        description "Pipe for AS'.$data['asn'].' - '.$data['name'].'";
        table master6;
        peer table t_0099_as'.$data['asn'].';
        import filter f_export_to_master;
        export where ixp_community_filter('.$data['asn'].');
}

protocol bgp pb_0099_as'.$data['asn'].' from tb_rsclient {
        description "AS'.$data['asn'].' - '.$data['name'].'";
        neighbor '.$data['peer6'].' as '.$data['asn'].';
        ipv6 {
            import limit 10 action restart;
            import filter f_import_as'.$data['asn'].';
            table t_0099_as'.$data['asn'].';
            export filter f_export_as'.$data['asn'].';
        };

}
';

    file_put_contents('temp',$addtext);
    $output=array();
    exec('rsync temp root@['.$BGPIPv6.']:/etc/bird/temp',$output,$returnvar);
    if($returnvar!=0)
        die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);
    $output=array();
    exec('ssh root@'.$BGPIPv6.' \'cp /etc/bird/bird.conf.template /etc/bird/bird.conf\'',$output,$returnvar);
    if($returnvar!=0)
        die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);
    $output=array();
    exec('ssh root@'.$BGPIPv6.' \'cat /etc/bird/temp >> /etc/bird/bird.conf\'',$output,$returnvar);
    if($returnvar!=0)
        die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);
    $output=array();
    exec('ssh root@'.$BGPIPv6.' \'systemctl restart bird\'',$output,$returnvar);//only take new AS if restart. not work with reload
    if($returnvar!=0)
        die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);
    exec('ssh root@'.$BGPIPv6.' \'echo "" > /var/log/bird/bgp*-ipv*.log\'',$output,$returnvar);//only take new AS if restart. not work with reload
    if($returnvar!=0)
        die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);
}
sleep(120);
if(isset($data['peer4']))
{
    foreach($listsrvBGP4 as $BGPIP)
    {
        $trycount=0;
        while($trycount<120)
        {
            $trycount++;
            $output=array();
            exec('ssh root@'.$BGPIP.' \'birdc s p\' | grep -F \'pb_0099_as'.$data['asn'].'\' | grep -F -v \'BIRD \' | grep -F -v \'Name       Proto      Table      State  Since         Info\'',$output,$returnvar);
            if($returnvar!=0)
            {
                if($trycount<120)
                {
                    sleep(1);
                    continue;
                }
                die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);
            }
            if(strlen(implode('',$output))<2)
            {
                if($trycount<120)
                {
                    sleep(1);
                    continue;
                }
                echo '<pre>'.h(implode("\n",$output)).'</pre>';
                $output2=array();
                exec('ssh root@'.$BGPIP.' \'ping -4 -c 3 '.$data['peer4'].'\'',$output2,$returnvar);
                echo '<pre>'.h(implode("\n",$output)).'</pre>';
                die('no vemos su session BGP activa, verificar que esta activa con:<ul>
                <li>172.23.0.1</li>
                <li>172.23.0.2</li>
                </ul>
                incluso si no tiene IP por publicar');
            }
            else if(strpos(implode("\n",$output),' up ')===FALSE)
            {
                if($trycount<120)
                {
                    sleep(1);
                    continue;
                }
                echo '<pre>'.h(implode("\n",$output)).'</pre>';
                $output2=array();
                exec('ssh root@'.$BGPIP.' \'ping -4 -c 3 '.$data['peer4'].'\'',$output2,$returnvar);
                echo '<pre>'.h(implode("\n",$output)).'</pre>';
                die('no vemos su session BGP valida en '.$BGPIP.', verificar que esta valida con:<ul>
                <li>172.23.0.1</li>
                <li>172.23.0.2</li>
                </ul>
                incluso si no tiene IP por publicar');
            }
        }
        
        $output=array();
        exec('ssh root@'.$BGPIP.' \'birdc show protocol all pb_0099_as'.$data['asn'].'\' | grep -F \'Import updates:\'',$output,$returnvar);
        if($returnvar!=0)
            die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);
        if(strlen(implode('',$output))<2)
        {
            echo '<pre>'.h(implode("\n",$output)).'</pre>';
            $output2=array();
            exec('ssh root@'.$BGPIP.' \'ping -4 -c 3 '.$data['peer4'].'\'',$output2,$returnvar);
            echo '<pre>'.h(implode("\n",$output)).'</pre>';
            die('no vemos su session BGP activa, verificar que esta activa con:<ul>
            <li>172.23.0.1</li>
            <li>172.23.0.2</li>
            </ul>
            incluso si no tiene IP por publicar');
        }
        else
        {
            $numbers = preg_split("#[^0-9]+#",implode('',$output),-1,PREG_SPLIT_NO_EMPTY);
            if(count($numbers)!=5)
                die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);
            else
            {
                $received=(int)$numbers[0];
                $rejected=(int)$numbers[1];
                $filtered=(int)$numbers[2];
                $ignored=(int)$numbers[3];
                $accepted=(int)$numbers[4];
                if($rejected>0)
                    die('tiene routa rejectada, verificar lista de routas enviadas');
                if($filtered>0)
                    die('tiene routa filtrada, verificar lista de routas enviadas');
                if($ignored>0)
                    die('tiene routa ignorada, verificar lista de routas enviadas');
                if($accepted>10)
                    die('tiene routa demasido routas acceptada, verificar lista de routas enviadas');
            }
        }
        
        $output=array();
        exec('ssh root@'.$BGPIP.' \'birdc show route protocol pb_0099_as'.$data['asn'].'\' | grep -F \'pb_0099_as'.$data['asn'].'\' | grep -F -v \') [AS'.$data['asn'].'i]\'',$output,$returnvar);
        if($returnvar>2)
        {
            echo '<pre>'.h(implode("\n",$output)).'</pre>';
            die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__.' y '.$returnvar);
        }
        if(strlen(implode('',$output))>2)
        {
            echo 'escape de routas:';
            echo '<pre>'.h(implode("\n",$output)).'</pre>';
            die('corrigir estas routas');
        }
    }
}
if(isset($data['peer6']))
{
    foreach($listsrvBGP6 as $BGPIP)
    {
        $trycount=0;
        while($trycount<120)
        {
            $trycount++;
            $output=array();
            exec('ssh root@'.$BGPIP.' \'birdc s p\' | grep -F \'pb_0099_as'.$data['asn'].'\' | grep -F -v \'BIRD \' | grep -F -v \'Name       Proto      Table      State  Since         Info\'',$output,$returnvar);
            if($returnvar!=0)
            {
                if($trycount<120)
                {
                    sleep(1);
                    continue;
                }
                die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);
            }
            if(strlen(implode('',$output))<2)
            {
                if($trycount<120)
                {
                    sleep(1);
                    continue;
                }
                echo '<pre>'.h(implode("\n",$output)).'</pre>';
                $output2=array();
                exec('ssh root@'.$BGPIP.' \'ping -6 -c 3 '.$data['peer6'].'\'',$output,$returnvar);
                echo '<pre>'.h(implode("\n",$output2)).'</pre>';
                die('no vemos su session BGP activa, verificar que esta activa con:<ul>
                <li>2803:1920:0:1::1</li>
                <li>2803:1920:0:1::2</li>
                </ul>
                incluso si no tiene IP por publicar');
            }
            else if(strpos(implode("\n",$output),' up ')===FALSE)
            {
                if($trycount<120)
                {
                    sleep(1);
                    continue;
                }
                echo '<pre>'.h(implode("\n",$output)).'</pre>';
                $output2=array();
                exec('ssh root@'.$BGPIP.' \'ping -6 -c 3 '.$data['peer6'].'\'',$output2,$returnvar);
                echo '<pre>'.h(implode("\n",$output)).'</pre>';
                die('no vemos su session BGP valida en '.$BGPIP.', verificar que esta valida con:<ul>
                <li>2803:1920:0:1::1</li>
                <li>2803:1920:0:1::2</li>
                </ul>
                incluso si no tiene IP por publicar');
            }
        }
        
        $output=array();
        exec('ssh root@'.$BGPIP.' \'birdc show protocol all pb_0099_as'.$data['asn'].'\' | grep -F \'Import updates:\'',$output,$returnvar);
        if($returnvar!=0)
            die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);
        if(strlen(implode('',$output))<2)
        {
            echo '<pre>'.h(implode("\n",$output)).'</pre>';
            $output2=array();
            exec('ssh root@'.$BGPIP.' \'ping -4 -c 3 '.$data['peer4'].'\'',$output2,$returnvar);
            echo '<pre>'.h(implode("\n",$output)).'</pre>';
            die('no vemos su session BGP activa, verificar que esta activa con:<ul>
            <li>172.23.0.1</li>
            <li>172.23.0.2</li>
            </ul>
            incluso si no tiene IP por publicar');
        }
        else
        {
            $numbers = preg_split("#[^0-9]+#",implode('',$output),-1,PREG_SPLIT_NO_EMPTY);
            if(count($numbers)!=5)
                die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);
            else
            {
                $received=(int)$numbers[0];
                $rejected=(int)$numbers[1];
                $filtered=(int)$numbers[2];
                $ignored=(int)$numbers[3];
                $accepted=(int)$numbers[4];
                if($rejected>0)
                    die('tiene routa rejectada, verificar lista de routas enviadas');
                if($filtered>0)
                    die('tiene routa filtrada, verificar lista de routas enviadas');
                if($ignored>0)
                    die('tiene routa ignorada, verificar lista de routas enviadas');
                if($accepted>10)
                    die('tiene routa demasido routas acceptada, verificar lista de routas enviadas');
            }
        }
        
        $output=array();
        exec('ssh root@'.$BGPIP.' \'birdc show route protocol pb_0099_as'.$data['asn'].'\' | grep -F \'pb_0099_as'.$data['asn'].'\' | grep -F -v \') [AS'.$data['asn'].'i]\'',$output,$returnvar);
        if($returnvar>2)
        {
            echo '<pre>'.h(implode("\n",$output)).'</pre>';
            die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__.' y '.$returnvar);
        }
        if(strlen(implode('',$output))>2)
        {
            echo 'escape de routas:';
            echo '<pre>'.h(implode("\n",$output)).'</pre>';
            die('corrigir estas routas');
        }
    }
}
//check route and test ping
foreach($listFakeAS as $fakeIP=>$ISPdata)
{
    //IPv4
    if(isset($data['ipv4rangelist']))
    {
        $output=array();
        exec('ssh root@'.$fakeIP.' \'route -n -4\' | grep -F \'eth0\' | grep -F -v \'172.23.0.0\' | grep -F -v \'198.51.100.0\' | grep -F -v \'203.0.113.0\' | grep -F -v \'192.0.2.0\' | awk \'{print $1}\'',$output,$returnvar);
        if($returnvar!=0)
            die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);
        //search missing IPv4 range
        $ipv4rangelistclean=[];
        foreach($data['ipv4rangelist'] as $t)
        {
            $t=preg_replace('#/.*$#','',$t);
            $ipv4rangelistclean[]=$t;
            if(!in_array($t,$output))
                die('No vemos su bloque '.h($t).' en nuestro entourno de preuva '.$fakeIP.' verificar sur lista de bloque publicado');
        }
        //search too much IPv4 range
        foreach($output as $t)
        {
            if(!in_array($t,$ipv4rangelistclean))
                die('Vemos un bloque '.h($t).' en nuestro entourno de preuva '.$fakeIP.' verificar sur lista de bloque publicado');
        }
    }
    
    //IPv6
    //search missing IPv6 range
    if(isset($data['ipv6rangelist']))
    {
        $output=array();
        exec('ssh root@'.$fakeIP.' \'route -n -6\' | grep -F \'eth0\' | grep -F -v \'2803:1920:0:1::/64\' | grep -F -v \'fe80::/64\' | grep -F -v \'3fff::/32\' | grep -F -v \'3fff:1::/32\' | grep -F -v \'3fff:2::/32\' | awk \'{print $1}\'',$output,$returnvar);
        if($returnvar!=0)
            die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);
        foreach($data['ipv6rangelist'] as $t)
        {
            if(!in_array($t,$output))
                die('No vemos su bloque '.h($t).' en nuestro entourno de preuva '.$fakeIP.' verificar sur lista de bloque publicado');
        }
        //search too much IPv6 range
        foreach($output as $t)
        {
            if(!in_array($t,$data['ipv6rangelist']))
                die('Vemos un bloque '.h($t).' en nuestro entourno de preuva '.$fakeIP.' verificar sur lista de bloque publicado');
        }
    }
    
    if(isset($data['ipv4list']))
        foreach($data['ipv4list'] as $IPv4)
        {
            //ping
            $output=array();
            exec('ssh root@'.$fakeIP.' \'ping -I '.$ISPdata['IPv4'].' -c 1 '.$IPv4.'\'',$output,$returnvar);
            if($returnvar!=0)
                die('die at line '.__LINE__);
            if(strpos(implode('',$output),'0% packet loss')===FALSE)
                die('No logramos hacer ping deste '.$fakeIP.' hasta sur IP '.$IPv4);
        }
    if($data['ipv6list'])
        foreach($data['ipv6list'] as $IPv6)
        {
            //ping
            $output=array();
            exec('ssh root@'.$fakeIP.' \'ping -I '.$ISPdata['IPv6'].' -c 1 '.$IPv6.'\'',$output,$returnvar);
            if($returnvar!=0)
                die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);
            if(strpos(implode('',$output),'0% packet loss')===FALSE)
                die('No logramos hacer ping deste '.$fakeIP.' hasta sur IP '.$IPv6);
        }
}
//final check
sleep(60);
foreach($listsrvBGP as $BGPIP)
{
    $output=array();
    exec('ssh root@'.$BGPIP.' \'birdc s p\' | grep -F -v \'up\' | grep -F -v \'Active\' | grep -F -v \'BIRD \' | grep -F -v \'Name       Proto      Table      State  Since         Info\' | wc -l',$output,$returnvar);
    if($returnvar!=0)
        die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);
    if(implode('',$output)!=0)
        die('no vemos su session BGP activa, verificar que esta activa con:<ul>
        <li>172.23.0.1</li>
        <li>172.23.0.2</li>
        <li>2803:1920:0:1::1</li>
        <li>2803:1920:0:1::2</li>
        </ul>
        incluso si no tiene IP por publicar');
    $output=array();
    exec('ssh root@'.$BGPIP.' \'cat /var/log/tcpdump.log | grep -F -v "packets captured" | grep -F -v "packets received by filter" | grep -F -v "0 packets dropped by kernel" | grep -F -v " '.$data['peer4'].'" | grep -F -v " 172.23.0.1.179" | grep -F -v " 172.23.0.2.179" | grep -F -v "ARP, Request" | grep -F -v "ARP, Reply" | grep -F -v "verbose output suppressed" | grep -F -v "listening on eth0"\'',$output,$returnvar);
    if($returnvar!=0)
        die('problema del entorno de preuba, perfavor informar el admin y indicarle el numero '.__LINE__);
    $output=implode("\n",$output);
    if(strlen($output)>2)
    {
        echo 'vemos trafico incorrecto en nuestro entourno de preuba '.$BGPIP.', le recordamos que no deves enviar multicast/broadcast, ni trafico fuera de las routas enviadas, contactar el admin para mas detailes';
        echo '<pre>'.h(implode("\n",$output)).'</pre>';
        exit;
    }
}

//stop all
foreach($listsrvBGP as $BGPIP)
{
    $output=array();
    exec('ssh root@'.$BGPIP.' \'systemctl stop tcpdump\' | wc -l',$output,$returnvar);
    //exec('ssh root@'.$BGPIP.' \'echo "" > /var/log/tcpdump.log\'',$output,$returnvar);
}
echo 'todo los preubas estan OK, contactar el admin para pasar a production';
