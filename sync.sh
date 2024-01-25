# usage: 
#       ./sync.sh out num_server
#       ./sync.sh in num_server cli_num(1,2,4,8,16) coro_num(1,2,3,4)
clis=("192.168.1.51" "192.168.1.52" "192.168.1.53" "192.168.1.11" "192.168.1.12"  "192.168.1.13" "192.168.1.14" "192.168.1.10" )
if [ "$1" = "out" ]
then
    make ser_cli_var_kv
    make ser_cli
    for cli in ${clis[@]:0:$2}
    do 
        echo "cli" $cli
        sshpass -p 'mxh' scp ./ser_cli mxh@$cli:/home/mxh/
        sshpass -p 'mxh' scp ./ser_cli_var_kv mxh@$cli:/home/mxh/
        sshpass -p 'mxh' scp ../ser_cli.sh mxh@$cli:/home/mxh/
        sshpass -p 'mxh' scp ../run.sh mxh@$cli:/home/mxh/
    done
else
    cnt=1
    rm -f ./insert_lat*192.168*.txt
    rm -f ./search_lat*192.168*.txt
    for cli in ${clis[@]:0:$2}
    do 
        echo "cli" $cli
        rm -f ./out$cli.txt
        sshpass -p 'mxh' scp mxh@$cli:/home/mxh/out.txt ./out$cli.txt
        cli_num=$3
        coro_num=$4
        for ((cli_id=0; cli_id<cli_num; cli_id++)); do
            for ((coro_id=0; coro_id<coro_num; coro_id++)); do
                # 设置要匹配的文件名
                filename="insert_lat${cli_id}${coro_id}.txt"
                echo $filename
                # 执行SCP命令，从远程服务器复制文件到本地并修改文件名
                sshpass -p "mxh" scp "mxh@$cli:/home/mxh/$filename" "./insert_lat${cli_id}${coro_id}$cli.txt"
                
                filename="search_lat${cli_id}${coro_id}.txt"
                echo $filename
                # 执行SCP命令，从远程服务器复制文件到本地并修改文件名
                sshpass -p "mxh" scp "mxh@$cli:/home/mxh/$filename" "./search_lat${cli_id}${coro_id}$cli.txt"
            done
        done
        ((cnt += 1))
    done
fi
