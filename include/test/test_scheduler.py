from apscheduler.schedulers.blocking import BlockingScheduler

def test_job():
    print("I'm a job")

b_scheduler = BlockingScheduler()
b_scheduler.add_job(test_job, 'interval', seconds=0) # actually wait 1 sec / use 0.01 works

b_scheduler.start()
