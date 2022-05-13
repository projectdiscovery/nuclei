
C:\Users\jaz\GolandProjects\nuclei\v2\pkg\rest\api\services\scans\worker.go :75
```
s.Running.Store(scanID, &RunningScan{
		ctx:          ctx,
		cancel:       cancel,
		ProgressFunc: makePercentReturnFunc(progressImpl),
	})
```

> 在`RunningScan`里加入sync.Map（tmpStatus），key=templateID,value=status

---

单条执行路径C:\Users\jaz\GolandProjects\nuclei\v2\pkg\core\execute.go  ：48

```
go func(tpl *templates.Template) {
//插入tmpStatus，status=running
			switch {
			case tpl.SelfContained:
				// Self Contained requests are executed here separately
				e.executeSelfContainedTemplateWithInput(tpl, results)
			default:
				// All other request types are executed here
				e.executeModelWithInput(ctx, templateType, tpl, target, results)
			}
			wg.Done()
			//插入修改tmpStatus，status=done
		}(template)
```
---

# TODO

C:\Users\jaz\GolandProjects\nuclei\v2\pkg\rest\api\services\scans\worker_output.go  ：46

执行命中结果被封装在这里写入；给`wrappedOutputWriter`结构体加入sync.Map，
构建时把RunningScan的tmpStatus给过来（newWrappedOutputWriter的修改）