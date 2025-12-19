cd "static/video/encode"
for (($n = 0); $n -le 7; $n++)
{
ffmpeg -y -i $n'.mp4' -map 0 -preset slow -vf "scale=1920:-1" -b:a 96k -movflags +faststart -vcodec h264 -pix_fmt yuv420p -crf 25 $n'e.mp4'
}
