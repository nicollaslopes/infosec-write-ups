i=1
printf '%s\n' *.png | sort -V | while IFS= read -r f; do
  mv "$f" "year_of_the_jellyfish-$i.png"
  ((i++))
done
