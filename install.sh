sudo pip install virtualenv virtualenvwrapper
 
sudo pip install --upgrade pip
  
printf '\n%s\n%s\n%s' '# virtualenv' 'export WORKON_HOME=~/virtualenvs' 'source /usr/local/bin/virtualenvwrapper.sh' >> ~/.bashrc

export WORKON_HOME=~/virtualenvs
source /usr/local/bin/virtualenvwrapper.sh
 
mkvirtualenv rocket_shot

workon rocket_shot

pip install angr termcolor IPython

echo "####################"
echo "run: . ~/.bashrc"
echo "run: workon rocket_shot"

