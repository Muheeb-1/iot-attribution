"""
METHOD COMPARISON - IoT Incident Attribution
============================================
Built and run 23 Aug 2026 to answer: "is there a better method than V1?"
Answer: yes. V5 is the winner. Use V5.

This is a HARD benchmark, deliberately much harder than sim.py:
  - 12 devices instead of 7
  - noisy, irregular baseline traffic
  - decoy traffic spikes on innocent devices (to fool volume-based methods)
  - legitimate device-to-device chatter (to create false causal edges)
  - a STEALTHY attacker: slower beacon, smaller packets, only 5 scan targets
  - 40% of runs relay the hop through a shared broker, leaving NO direct flow

Measured over 30 runs (random origin every run):
  method            top-1   top-3   mean rank   abstained
  rank by volume       0%     10%      6.07         -
  rank by anomaly     10%     47%      4.10         -
  rank by conn count   3%     10%      5.63         -
  rank by earliest    17%     53%      3.27         -
  V1 causal           43%     80%      2.33      21/30
  V2 whole-story      47%     90%      2.13      13/30
  V3 +provoked        47%     83%      2.17      16/30   <- no help, kept as evidence
  V4 +indicator       53%     73%      2.23      11/30
  V5 ENSEMBLE         53%     90%      2.00       5/30   <- BUILD THIS ONE

What V5 does that V1 does not:
  1. Scores the WHOLE STORY a device explains, not the device alone.
  2. Adds "shared indicator" links: if two devices both contact the same
     external address neither ever contacted before, they are linked and
     whoever touched it FIRST is upstream. This survives relayed hops.
  3. Ranks with (1) for a reliable shortlist, then re-ranks the top 3 with
     (2) to pick the winner. Best of both.

Run it:  python hard.py 30
"""
import numpy as np, pandas as pd, networkx as nx, itertools, sys
from sklearn.ensemble import IsolationForest

WIN=60; BASE_H=3; TOT_H=6; BROKER="broker"; C2="ext_c2"
KINDS=[("esp32-01","sensor"),("esp32-02","sensor"),("esp32-03","sensor"),("esp32-04","sensor"),
       ("camera","cam"),("cam2","cam"),("plug","plug"),("bulb","plug"),
       ("laptop-c","lap"),("laptop-d","lap"),("phone","lap"),("tablet","lap")]
NAMES=[d for d,_ in KINDS]
CLOUD={"cam":"cloud_cam","plug":"cloud_plug","lap":"cloud_web","sensor":BROKER}

def normal(rng):
    rows=[];T=TOT_H*3600
    for dev,k in KINDS:
        per={"sensor":10,"cam":5,"plug":60,"lap":30}[k]
        sz ={"sensor":(214,18),"cam":(240000,20000),"plug":(1200,200),"lap":(9000,6000)}[k]
        t=rng.uniform(0,per)
        while t<T:
            n=int(rng.integers(1,5)) if k=="lap" else 1
            for _ in range(n):
                rows.append((t,dev,CLOUD[k],int(abs(rng.normal(*sz))+50),int(abs(rng.normal(sz[0]*0.3,sz[1]))+20),4))
            t+=per*rng.uniform(0.45,1.9)          # NOISIER schedules
        for _ in range(int(rng.integers(6,20))):  # MORE legit new destinations
            rows.append((rng.uniform(0,T),dev,f"upd_{rng.integers(0,120)}",
                         int(abs(rng.normal(4000,3000))+200),int(abs(rng.normal(9000,7000))+500),6))
        if rng.random()<0.35:                     # legit device-to-device chatter sometimes
            peer=NAMES[int(rng.integers(0,len(NAMES)))]
            if peer!=dev:
                t=rng.uniform(0,T)
                for _ in range(int(rng.integers(5,40))):
                    rows.append((t,dev,peer,int(abs(rng.normal(800,300))+50),300,3)); t+=rng.uniform(1,25)
        if rng.random()<0.30:                     # legit traffic spike (decoy for volume methods)
            t=rng.uniform(BASE_H*3600,T-600)
            for k2 in range(400):
                rows.append((t+k2*0.5,dev,CLOUD[KINDS[NAMES.index(dev)][1]],int(rng.normal(300000,50000)),1500,200))
    return rows

def attack(rows,rng):
    T=TOT_H*3600
    origin=NAMES[int(rng.integers(0,len(NAMES)))]
    rest=[d for d in NAMES if d!=origin]; rng.shuffle(rest)
    v2,v3=rest[0],rest[1]
    t0=rng.uniform(BASE_H*3600+900,T-2400)
    via_broker = rng.random()<0.40                 # 40%: hop goes through the broker
    t=t0
    while t<T:                                     # STEALTHIER beacon: slower, smaller
        rows.append((t,origin,C2,int(rng.normal(140,15)),int(rng.normal(90,12)),2))
        t+=90*rng.uniform(0.8,1.2)
    ts=t0+120                                      # quieter scan: only 5 peers
    for peer in rng.choice([d for d in NAMES if d!=origin],5,replace=False):
        for k in range(2): rows.append((ts+k*0.5,origin,str(peer),60,0,1))
    tb=t0+300
    if via_broker:
        for k in range(120): rows.append((tb+k*0.5,origin,BROKER,int(rng.normal(500,60)),200,3))
        for k in range(120): rows.append((tb+8+k*0.5,BROKER,v2,int(rng.normal(500,60)),200,3))
    else:
        for k in range(160): rows.append((tb+k*0.4,origin,v2,int(rng.normal(420,40)),300,3))
    t2=t0+480; t=t2
    while t<T:
        rows.append((t,v2,C2,int(rng.normal(140,15)),int(rng.normal(90,12)),2)); t+=90*rng.uniform(0.8,1.2)
    te=t2+60
    for k in range(600): rows.append((te+k*0.4,v2,C2,int(rng.normal(420000,40000)),1200,300))
    t3=t0+780
    for k in range(700): rows.append((t3+k*0.2,v2,v3,int(rng.normal(700,80)),2500,5))
    return rows,{"origin":origin,"chain":[origin,v2,v3],"via_broker":via_broker}

def make(seed):
    rng=np.random.default_rng(seed)
    r=normal(rng); r,tr=attack(r,rng)
    return pd.DataFrame(r,columns=["t","src","dst","bytes_out","bytes_in","pkts"]).sort_values("t").reset_index(drop=True),tr

FEATS=["bytes_out","bytes_in","n_conn","n_dst","n_new_ext","n_peer","iat_reg"]
# how diagnostic each feature is of an actual compromise (used by V2 only)
DIAG={"bytes_out":1.0,"bytes_in":1.0,"n_conn":1.2,"n_dst":1.5,"n_new_ext":3.0,"n_peer":2.5,"iat_reg":2.0}

def features(df):
    df=df.copy(); df["w"]=(df["t"]//WIN).astype(int); bw=BASE_H*3600//WIN
    seen={d:set(df[(df.src==d)&(df.w<bw)].dst.unique()) for d in NAMES}
    out=[]
    for (dev,w),g in df.groupby(["src","w"],sort=True):
        if dev not in NAMES: continue
        ds=set(g.dst.unique()); ts=np.sort(g.t.values); iat=np.diff(ts)
        cv=(iat.std()/iat.mean()) if len(iat)>3 and iat.mean()>0 else 1.0
        new_ext={x for x in ds-seen[dev] if x not in NAMES}
        out.append(dict(dev=dev,w=w,bytes_out=g.bytes_out.sum(),bytes_in=g.bytes_in.sum(),
            n_conn=len(g),n_dst=len(ds),n_new_ext=len(new_ext),
            n_peer=int(g.dst.isin(NAMES).sum()),iat_reg=1.0/(cv+0.05)))
    return pd.DataFrame(out)

def detect(F,weighted,thresh=4.0,k=3):
    bw=BASE_H*3600//WIN; scores={}; onsets={}
    for dev,g in F.groupby("dev"):
        g=g.sort_values("w"); b=g[g.w<bw]
        if len(b)<8: continue
        med=b[FEATS].median(); mad=(b[FEATS]-med).abs().median()*1.4826
        mad=mad.replace(0,np.nan).fillna(b[FEATS].std().replace(0,1)).clip(lower=1e-6)
        Z=(g[FEATS]-med).abs()/mad
        if weighted:                                  # V2: weight by how diagnostic each feature is
            s=(Z*pd.Series(DIAG)).max(axis=1).values/1.6
        else:
            s=Z.max(axis=1).values
        try:
            iso=IsolationForest(n_estimators=50,random_state=0).fit(b[FEATS])
            s2=-iso.score_samples(g[FEATS]); s2=(s2-s2[:len(b)].mean())/(s2[:len(b)].std()+1e-9)
            s=np.maximum(s,s2*1.5)
        except Exception: pass
        ws=g.w.values; scores[dev]=dict(zip(ws.tolist(),s.tolist())); on=None
        for i in range(len(s)-k+1):
            if ws[i]<bw: continue
            if all(s[i+j]>thresh for j in range(k)): on=float(ws[i]*WIN); break
        if on is not None: onsets[dev]=on
    return scores,onsets

def build_graph(df,onsets,allow_broker,dmax=1800):
    devs=list(onsets); G=nx.DiGraph(); G.add_nodes_from(devs)
    for u in devs:
        for v in devs:
            if u==v or not (onsets[u]<onsets[v]<=onsets[u]+dmax): continue
            direct=df[(df.src==u)&(df.dst==v)&(df.t>=onsets[u])&(df.t<=onsets[v])]
            if len(direct)>0: G.add_edge(u,v,w=1.0+min(len(direct)/50,1.0)); continue
            if allow_broker:                          # V2: one hop via a shared non-device host
                a=set(df[(df.src==u)&(df.t>=onsets[u])&(df.t<=onsets[v])].dst)-set(NAMES)
                bset=set(df[(df.dst==v)&(df.t>=onsets[u])&(df.t<=onsets[v])].src)-set(NAMES)
                if a & bset: G.add_edge(u,v,w=0.5)
    return G

def score_v1(df,G,onsets):
    devs=list(onsets)
    if not devs: return [],0.0
    bw=BASE_H*3600//WIN; tmn,tmx=min(onsets.values()),max(onsets.values()); span=max(tmx-tmn,1)
    S={}
    for d in devs:
        reach=len(nx.descendants(G,d))/max(len(devs)-1,1)
        orph=1.0 if G.in_degree(d)==0 else 0.0
        early=(tmx-onsets[d])/span
        post=df[(df.src==d)&(df.t>=onsets[d])]; pre=set(df[(df.src==d)&(df.t<bw*WIN)].dst)
        nov=(len(set(post.dst)-pre)/max(len(set(post.dst)),1)) if len(post) else 0
        S[d]=0.40*reach+0.30*orph+0.15*early+0.15*nov
    r=sorted(S,key=lambda d:-S[d])
    conf=(S[r[0]]-S[r[1]])/max(S[r[0]],1e-9) if len(r)>1 else 1.0
    return r,conf

def score_v2(df,G,onsets,scores):
    """Whole-story scoring: for each candidate root, score the BEST explanation
    tree it produces, not the device in isolation."""
    devs=list(onsets)
    if not devs: return [],0.0
    bw=BASE_H*3600//WIN; tmn,tmx=min(onsets.values()),max(onsets.values()); span=max(tmx-tmn,1)
    n=len(devs); S={}
    for d in devs:
        tree=nx.bfs_tree(G,d) if d in G else nx.DiGraph()
        covered=set(tree.nodes())
        coverage=len(covered)/n                                  # how much of the incident it explains
        strength=np.mean([G[u][v]["w"] for u,v in tree.edges()]) if tree.number_of_edges() else 0.0
        orph=1.0 if G.in_degree(d)==0 else 0.0
        early=(tmx-onsets[d])/span
        post=df[(df.src==d)&(df.t>=onsets[d])]; pre=set(df[(df.src==d)&(df.t<bw*WIN)].dst)
        newext=len({x for x in set(post.dst)-pre if x not in NAMES})
        nov=min(newext/2.0,1.0)
        quiet=1.0-min(df[(df.src==d)&(df.t>=onsets[d])].bytes_out.sum()/
                      max(df[df.src.isin(NAMES)&(df.t>=tmn)].groupby('src').bytes_out.sum().max(),1),1.0)
        S[d]=(0.34*coverage + 0.20*strength + 0.22*orph + 0.10*early + 0.10*nov + 0.04*quiet)
    r=sorted(S,key=lambda d:-S[d])
    # counterfactual confirm on top-3
    for d in r[:3]:
        H=G.copy(); H.remove_edges_from(list(G.out_edges(d)))
        roots=[x for x in H if H.in_degree(x)==0]
        unexp=sum(1 for x in H if not any(nx.has_path(H,rt,x) for rt in roots))
        S[d]+=0.03*unexp
    r=sorted(S,key=lambda d:-S[d])
    conf=(S[r[0]]-S[r[1]])/max(S[r[0]],1e-9) if len(r)>1 else 1.0
    return r,conf


def provoked(df,d,onset,bw):
    """Did device d receive UNUSUAL inbound traffic just before it went bad?
    If yes, something reached it -> it is not patient zero."""
    inb=df[(df.dst==d)]
    base=inb[inb.t<bw*WIN]
    if len(base)<5: base_rate=0.0
    else: base_rate=len(base)/max(bw*WIN,1)*600.0
    win=inb[(inb.t>=onset-600)&(inb.t<onset+120)]
    obs=len(win)
    return min(max((obs-base_rate)/max(base_rate+3.0,1.0),0.0),3.0)/3.0

def score_v3(df,G,onsets,scores):
    devs=list(onsets)
    if not devs: return [],0.0
    bw=BASE_H*3600//WIN; tmn,tmx=min(onsets.values()),max(onsets.values()); span=max(tmx-tmn,1)
    n=len(devs); S={}
    for d in devs:
        tree=nx.bfs_tree(G,d) if d in G else nx.DiGraph()
        coverage=len(set(tree.nodes()))/n
        strength=np.mean([G[u][v]["w"] for u,v in tree.edges()]) if tree.number_of_edges() else 0.0
        orph=1.0 if G.in_degree(d)==0 else 0.0
        prov=provoked(df,d,onsets[d],bw)          # NEW: raw-flow evidence it was attacked
        early=(tmx-onsets[d])/span
        post=df[(df.src==d)&(df.t>=onsets[d])]; pre=set(df[(df.src==d)&(df.t<bw*WIN)].dst)
        newext=len({x for x in set(post.dst)-pre if x not in NAMES})
        nov=min(newext/2.0,1.0)
        S[d]=(0.24*coverage + 0.12*strength + 0.16*orph + 0.28*(1.0-prov)
              + 0.12*early + 0.08*nov)
    r=sorted(S,key=lambda d:-S[d])
    for d in r[:3]:
        H=G.copy(); H.remove_edges_from(list(G.out_edges(d)))
        roots=[x for x in H if H.in_degree(x)==0]
        unexp=sum(1 for x in H if not any(nx.has_path(H,rt,x) for rt in roots))
        S[d]+=0.03*unexp
    r=sorted(S,key=lambda d:-S[d])
    conf=(S[r[0]]-S[r[1]])/max(S[r[0]],1e-9) if len(r)>1 else 1.0
    return r,conf


def add_indicator_edges(df,G,onsets,bw):
    """Real analysts pivot on shared indicators: if two compromised devices both
    contact the SAME external host that neither ever contacted before, they are
    linked - and whoever touched it FIRST is upstream. This works even when the
    hop between them was relayed and left no direct flow."""
    devs=list(onsets)
    pre={d:set(df[(df.src==d)&(df.t<bw*WIN)].dst) for d in devs}
    first={}
    for d in devs:
        post=df[(df.src==d)&(df.t>=onsets[d]-120)]
        for dst,g in post.groupby("dst"):
            if dst in NAMES or dst in pre[d]: continue
            first.setdefault(dst,{})[d]=g.t.min()
    for dst,hits in first.items():
        if len(hits)<2: continue
        # rare = almost nobody in the lab ever talked to it during baseline
        if sum(1 for d in devs if dst in pre[d])>0: continue
        order=sorted(hits,key=lambda d:hits[d])
        for i in range(len(order)-1):
            u,v=order[i],order[i+1]
            if onsets[u]<=onsets[v] and not G.has_edge(u,v):
                G.add_edge(u,v,w=1.6)
    return G

def score_v4(df,G,onsets,scores):
    devs=list(onsets)
    if not devs: return [],0.0
    bw=BASE_H*3600//WIN
    G=add_indicator_edges(df,G.copy(),onsets,bw)
    tmn,tmx=min(onsets.values()),max(onsets.values()); span=max(tmx-tmn,1)
    n=len(devs); S={}
    for d in devs:
        tree=nx.bfs_tree(G,d) if d in G else nx.DiGraph()
        coverage=len(set(tree.nodes()))/n
        strength=np.mean([G[u][v]["w"] for u,v in tree.edges()]) if tree.number_of_edges() else 0.0
        orph=1.0 if G.in_degree(d)==0 else 0.0
        early=(tmx-onsets[d])/span
        post=df[(df.src==d)&(df.t>=onsets[d])]; pre=set(df[(df.src==d)&(df.t<bw*WIN)].dst)
        newext=len({x for x in set(post.dst)-pre if x not in NAMES})
        nov=min(newext/2.0,1.0)
        S[d]=0.30*coverage+0.16*strength+0.28*orph+0.16*early+0.10*nov
    r=sorted(S,key=lambda d:-S[d])
    for d in r[:3]:
        H=G.copy(); H.remove_edges_from(list(G.out_edges(d)))
        roots=[x for x in H if H.in_degree(x)==0]
        unexp=sum(1 for x in H if not any(nx.has_path(H,rt,x) for rt in roots))
        S[d]+=0.03*unexp
    r=sorted(S,key=lambda d:-S[d])
    conf=(S[r[0]]-S[r[1]])/max(S[r[0]],1e-9) if len(r)>1 else 1.0
    return r,conf


def score_v5(df,G,onsets,scores):
    """V2 whole-story ranking (best shortlist) then re-rank the top 3 using
    shared-indicator evidence (best at picking the winner). Best of both."""
    r2,c2=score_v2(df,G,onsets,scores)
    if len(r2)<2: return r2,c2
    bw=BASE_H*3600//WIN
    H=add_indicator_edges(df,G.copy(),onsets,bw)
    top=r2[:3]
    bonus={}
    for d in top:
        anc=len(nx.ancestors(H,d)) if d in H else 0      # things pointing AT it = bad
        desc=len(nx.descendants(H,d)) if d in H else 0   # things it explains = good
        bonus[d]=desc-2.0*anc
    ranked=sorted(top,key=lambda d:(-bonus[d],r2.index(d)))+r2[3:]
    b=sorted(bonus.values(),reverse=True)
    conf=max(c2,(b[0]-b[1])/max(abs(b[0])+1,1)) if len(b)>1 else c2
    return ranked,conf

def baselines(df,onsets,scores):
    tot=df[df.src.isin(NAMES)].groupby("src").bytes_out.sum()
    nc=df[df.src.isin(NAMES)].groupby("src").size()
    return {"B1 volume":list(tot.sort_values(ascending=False).index),
            "B2 anomaly":sorted(scores,key=lambda d:-max(scores[d].values())) if scores else [],
            "B3 conn count":list(nc.sort_values(ascending=False).index),
            "B4 earliest":sorted(onsets,key=lambda d:onsets[d]) if onsets else []}

def rk(l,x): return l.index(x)+1 if x in l else 99

if __name__=="__main__":
    N=int(sys.argv[1]) if len(sys.argv)>1 else 20
    M=["B1 volume","B2 anomaly","B3 conn count","B4 earliest","V1 causal","V2 improved","V3 +provoked","V4 +indicator","V5 ensemble"]
    res={m:[] for m in M}; miss1=miss2=ab1=ab2=ab3=ab4=ab5=0
    for i in range(N):
        df,tr=make(5000+i)
        F=features(df)
        sc1,on1=detect(F,weighted=False)
        sc2,on2=detect(F,weighted=True)
        if tr["origin"] not in on1: miss1+=1
        if tr["origin"] not in on2: miss2+=1
        G1=build_graph(df,on1,allow_broker=False)
        G2=build_graph(df,on2,allow_broker=True)
        r1,c1=score_v1(df,G1,on1)
        r2,c2=score_v2(df,G2,on2,sc2)
        r3,c3=score_v3(df,G2,on2,sc2)
        r4,c4=score_v4(df,G2,on2,sc2)
        r5,c5=score_v5(df,G2,on2,sc2)
        b=baselines(df,on1,sc1)
        for m in M[:4]: res[m].append(rk(b[m],tr["origin"]))
        res["V1 causal"].append(rk(r1,tr["origin"]))
        res["V2 improved"].append(rk(r2,tr["origin"]))
        res["V3 +provoked"].append(rk(r3,tr["origin"]))
        res["V4 +indicator"].append(rk(r4,tr["origin"]))
        res["V5 ensemble"].append(rk(r5,tr["origin"]))
        if c1<0.15: ab1+=1
        if c2<0.15: ab2+=1
        if c3<0.15: ab3+=1
        if c4<0.15: ab4+=1
        if c5<0.15: ab5+=1
    print(f"\n  HARD benchmark · {N} runs · 12 devices · stealth beacon · 40% broker-relayed hops\n")
    print(f"  {'method':<20}{'top-1':>8}{'top-3':>8}{'mean rank':>12}")
    print("  "+"-"*48)
    for m in M:
        r=np.array(res[m]); ok=r[r<99]
        print(f"  {m:<20}{(r==1).mean()*100:>7.0f}%{(r<=3).mean()*100:>7.0f}%{(ok.mean() if len(ok) else float('nan')):>12.2f}")
    print(f"\n  detector missed origin:  V1 {miss1}/{N}   V2 {miss2}/{N}")
    print(f"  abstained:               V1 {ab1}/{N}   V2 {ab2}/{N}   V3 {ab3}/{N}   V4 {ab4}/{N}   V5 {ab5}/{N}")
