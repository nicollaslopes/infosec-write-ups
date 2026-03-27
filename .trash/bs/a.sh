i=1
printf '%s\n' *.png | sort -V | while IFS= read -r f; do
  mv "$f" "lazyadmin-$i.png"
  ((i++))
done
