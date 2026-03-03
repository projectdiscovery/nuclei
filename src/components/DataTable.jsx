// 在useEffect中添加清理逻辑
useEffect(() => {
  let isMounted = true;
  fetchData().then(res => {
    if (isMounted) setData(res);
  });
  return () => { isMounted = false; };
}, [page]);