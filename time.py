import datetime

lines = open('parallel_rr_output', 'r').readlines()

# breakpoint
breakpoints = [line.strip() for line in lines if "Running breakpoints took" in line]
breakpoints = [line.split()[-1] for line in breakpoints]
breakpoints = [datetime.datetime.strptime(word, '%H:%M:%S.%f') - datetime.datetime(1900, 1, 1) for word in breakpoints]
total_breakpoint_time = sum(breakpoints, datetime.timedelta())
print("Breakpoints took in total: {}".format(total_breakpoint_time))

# watchpoint
watchpoints = [line.strip() for line in lines if "Running watchpoints took" in line]
watchpoints = [line.split()[-1] for line in watchpoints]
watchpoints = [datetime.datetime.strptime(word, '%H:%M:%S.%f') - datetime.datetime(1900, 1, 1) for word in watchpoints]
total_watchpoint_time = sum(watchpoints, datetime.timedelta())
print("Watchpoints took in total: {}".format(total_watchpoint_time))

# task
tasks = [line.strip() for line in lines if "Process" in line and "finish task" in line and "in" in line]
tasks = [line.split()[-1] for line in tasks]
tasks = [datetime.datetime.strptime(word, '%H:%M:%S.%f') - datetime.datetime(1900, 1, 1) for word in tasks]
total_task_time = sum(tasks, datetime.timedelta())
print("Tasks took in total: {}".format(total_task_time))
