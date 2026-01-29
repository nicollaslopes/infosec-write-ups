i=1
printf '%s\n' *.png | sort -V | while IFS= read -r f; do
  mv "$f" "tomghost-$i.png"
  ((i++))
done
