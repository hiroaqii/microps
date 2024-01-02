#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "net.h"
#include "platform.h"
#include "util.h"

// 割り込み要求 (IRQ)
struct irq_entry {
    struct irq_entry *next;
    unsigned int irq;  // 割り込み番号 (IRQ番号)
    int (*handler)(unsigned int irq, void *dev);  // 割り込みハンドラ
    int flags;
    char name[16];  // デバック出力で識別するための名前
    void *dev;      // 割り込みの発生元となるデバイス
};

/* NOTE: if you want to add/delete the entries after intr_run(), you need to
 * protect these lists with a mutex. */
static struct irq_entry *irqs;  // IRQのリスト （リストの先頭を指すポインタ)

static sigset_t sigmask;  // シグナル集合（シグナルマスク用）

static pthread_t tid;              // 割り込みスレッドのID
static pthread_barrier_t barrier;  // スレッド間の同期のためのバリア

int intr_request_irq(unsigned int irq,
                     int (*handler)(unsigned int irq, void *dev), int flags,
                     const char *name, void *dev) {
    struct irq_entry *entry;

    // チェック処理
    debugf("irq=%u, flags=%d, name=%s", irq, flags, name);
    for (entry = irqs; entry; entry = entry->next) {
        if (entry->irq == irq) {
            if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED) {
                errorf("conflicts with already registered IRQs");
                return -1;
            }
        }
    }
    entry = memory_alloc(sizeof(*entry));
    if (!entry) {
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->irq = irq;
    entry->handler = handler;
    entry->flags = flags;
    strncpy(entry->name, name, sizeof(entry->name) - 1);
    entry->dev = dev;
    entry->next = irqs;  // リストの先頭に追加
    irqs = entry;
    sigaddset(&sigmask, irq);  // シグナル集合へ新しいシグナルを追加
    debugf("registered: irq=%u, name=%s", irq, name);
    return 0;
}

// 割り込みスレッドのエントリポイント
static void *intr_thread(void *arg) {
    int terminate = 0, sig, err;
    struct irq_entry *entry;

    debugf("start...");
    pthread_barrier_wait(&barrier);
    while (!terminate) {
        err = sigwait(&sigmask, &sig);
        if (err) {
            errorf("sigwait() %s", strerror(err));
            break;
        }
        switch (sig) {
            case SIGHUP:
                terminate = 1;
                break;
            case SIGUSR1:  // ソフトウェア割り込みシグナル
                net_softirq_handler();
                break;
            default:
                // IRQリスとを走査して、IRQ番号が一致するエントリの割り込みハンドラを呼び出す
                for (entry = irqs; entry; entry = entry->next) {
                    if (entry->irq == (unsigned int)sig) {
                        debugf("irq=%d, name=%s", entry->irq, entry->name);
                        entry->handler(entry->irq, entry->dev);
                    }
                }
                break;
        }
    }
    debugf("terminated");
    return NULL;
}

int intr_run(void) {
    int err;

    // シグナルマスクの設定
    err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
    if (err) {
        errorf("pthread_sigmask() %s", strerror(err));
        return -1;
    }

    // 割り込み処理スレッドの起動
    err = pthread_create(&tid, NULL, intr_thread, NULL);
    if (err) {
        errorf("pthread_create() %s", strerror(err));
        return -1;
    }
    // スレッドの起動を待つ
    pthread_barrier_wait(&barrier);

    return 0;
}

void intr_shutdown(void) {
    // 割り込み処理スレッドが起動済みか確認
    if (pthread_equal(tid, pthread_self()) != 0) {
        return;
    }
    pthread_kill(tid, SIGHUP);
    pthread_join(tid, NULL);
}

int intr_init(void) {
    tid = pthread_self();  // メインスレッドのIDを設定
    pthread_barrier_init(&barrier, NULL, 2);  // カウントを２で初期化
    sigemptyset(&sigmask);  // シグナルの初期化(空にする)
    // シグナルマスクにSIGHUPを追加(割り込み処理スレッドの終了用)
    sigaddset(&sigmask, SIGHUP);
    // シグナルマスクにSIGUSR1を追加(ソフトウェア割り込み用)
    sigaddset(&sigmask, SIGUSR1);

    return 0;
}

int intr_raise_irq(unsigned int irq) { return pthread_kill(tid, (int)irq); }
