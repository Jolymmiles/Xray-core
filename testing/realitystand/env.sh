# . env.sh: the stand's programs first on PATH and the library path.
export STAND_WORK=${STAND_WORK:-$HOME/.cache/realitystand}
R=$STAND_WORK/root
export PATH=$STAND_WORK/bin:$R/usr/sbin:$R/usr/bin:$R/sbin:$PATH
export LD_LIBRARY_PATH=$R/usr/lib/x86_64-linux-gnu:$R/lib/x86_64-linux-gnu:$R/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
