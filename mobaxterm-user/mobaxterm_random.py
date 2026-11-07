#!/bin/bash

IP="192.168.227.5"
PORT="3131"
USER="ar.hosseini"
FOLDER_NAME="MyServers"

# پالت رنگ‌های متمایز MobaXterm
colors=(
    "64"
    "32896"
    "4194304"
    "16711935"
    "10194943"
    "16384"
    "255"
    "65280"
    "16711680"
    "65535"
    "8388608"
    "32768"
)

color_count=${#colors[@]}
input_file="servers.txt"
output_file="My_Servers_pourabbas.mxtsessions"

if [ ! -f "$input_file" ]; then
    echo "خطا: فایل $input_file پیدا نشد."
    exit 1
fi

# پاکسازی کاراکترهای ویندوزی (CR/LF)
sed -i 's/\r$//' "$input_file"

# ساخت هدر فایل MobaXterm
cat << 'HeaderEOF' > "$output_file"
[Bookmarks]
SubRep=
ImgNum=42

[Bookmarks_1]
SubRep=MyServers
ImgNum=41
HeaderEOF

idx=0
count=0

while IFS= read -r server || [ -n "$server" ]; do
    # حذف فواصل اضافی از نام سرور
    server=$(echo "$server" | xargs)
    [ -z "$server" ] && continue

    # تبدیل به حروف کوچک برای بررسی دقیق‌تر شرط
    server_lower=$(echo "$server" | tr '[:upper:]' '[:lower:]')

    # فقط isvps, irvps, euvps با ssh3 متصل می‌شوند؛ مابقی همگی با ssh2
    if [[ "$server_lower" =~ ^(isvps|irvps|euvps) ]]; then
        cmd="sudo ssh3 $server"
    else
        cmd="sudo ssh2 $server"
    fi

    # انتخاب رنگ چرخشی
    color_idx=$((idx % color_count))
    color="${colors[$color_idx]}"

    # ساخت خط سشن با فرمت دقیق MobaXterm و رنگ سفارشی
    line="${server}= #109#0%${IP}%${PORT}%${USER}%%-1%-1%${cmd}%%%%0%0%0%%%-1%-1%0%0%%1080%%0%0%1%%0%%%%0%-1%-1%0%%%0#MobaFont%10%0%0%-1%15%236,236,236%30,30,30%180,180,192%0%-1%0%<>%xterm%-1%0%_Std_Colors_0_%80%24%0%1%-1%<none>%%0%0%-1%-1%#-1# #${color}"

    echo "$line" >> "$output_file"
    idx=$((idx + 1))
    count=$((count + 1))
done < "$input_file"

echo "تعداد $count سرور طبق الگوی جدید (ssh3 برای VPSها و ssh2 برای سایر سرویس‌ها) ساخته شدند."
